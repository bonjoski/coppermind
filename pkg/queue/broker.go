package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// TaskType represents standard background cognitive jobs.
type TaskType string

const (
	TaskSummarizeSession TaskType = "summarize_session"
	TaskDeepReflect      TaskType = "deep_reflect"
	TaskIndexGitTree     TaskType = "index_git_tree"
	TaskDefragMemory     TaskType = "defrag_memory"
	TaskExtractDecisions TaskType = "extract_decisions"
)

// TaskEnvelope carries metadata, payload, and traceability for background execution.
type TaskEnvelope struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	Type      TaskType               `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt time.Time              `json:"created_at"`
}

// TaskHandler is the worker callback function for processing an incoming task.
type TaskHandler func(ctx context.Context, task *TaskEnvelope) error

// Broker defines the contract for task queue messaging across embedded and RabbitMQ backends.
type Broker interface {
	Publish(ctx context.Context, topic string, task *TaskEnvelope) error
	Subscribe(ctx context.Context, topic string, handler TaskHandler) error
	Close() error
}

// EmbeddedBroker provides a zero-dependency in-memory asynchronous topic bus.
type EmbeddedBroker struct {
	mu          sync.RWMutex
	subscribers map[string][]TaskHandler
	taskCh      chan struct {
		topic string
		task  *TaskEnvelope
	}
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewEmbeddedBroker creates an in-memory queue broker.
func NewEmbeddedBroker(bufferSize int) *EmbeddedBroker {
	if bufferSize <= 0 {
		bufferSize = 256
	}
	b := &EmbeddedBroker{
		subscribers: make(map[string][]TaskHandler),
		taskCh: make(chan struct {
			topic string
			task  *TaskEnvelope
		}, bufferSize),
		stopCh: make(chan struct{}),
	}

	b.wg.Add(1)
	go b.dispatcher()
	return b
}

func (b *EmbeddedBroker) dispatcher() {
	defer b.wg.Done()
	for {
		select {
		case item := <-b.taskCh:
			b.mu.RLock()
			handlers := append([]TaskHandler(nil), b.subscribers[item.topic]...)
			// Also notify wildcard "#" subscribers
			wildcards := append([]TaskHandler(nil), b.subscribers["#"]...)
			b.mu.RUnlock()

			for _, h := range handlers {
				go func(handler TaskHandler, task *TaskEnvelope) {
					_ = handler(context.Background(), task)
				}(h, item.task)
			}
			for _, h := range wildcards {
				go func(handler TaskHandler, task *TaskEnvelope) {
					_ = handler(context.Background(), task)
				}(h, item.task)
			}
		case <-b.stopCh:
			return
		}
	}
}

// Publish queues a task onto the topic.
func (b *EmbeddedBroker) Publish(ctx context.Context, topic string, task *TaskEnvelope) error {
	if task.ID == "" {
		task.ID = generateTaskID()
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}

	select {
	case b.taskCh <- struct {
		topic string
		task  *TaskEnvelope
	}{topic: topic, task: task}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-b.stopCh:
		return fmt.Errorf("broker is stopped")
	}
}

// Subscribe registers a task handler for the topic.
func (b *EmbeddedBroker) Subscribe(_ context.Context, topic string, handler TaskHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.subscribers[topic] = append(b.subscribers[topic], handler)
	return nil
}

// Close shuts down the dispatcher.
func (b *EmbeddedBroker) Close() error {
	close(b.stopCh)
	b.wg.Wait()
	return nil
}

// RabbitMQBroker implements Broker backed by an external AMQP 0-9-1 RabbitMQ cluster.
type RabbitMQBroker struct {
	conn     *amqp.Connection
	ch       *amqp.Channel
	exchange string
	closeMu  sync.Mutex
	isClosed bool
}

// NewRabbitMQBroker connects to a RabbitMQ server.
func NewRabbitMQBroker(amqpURL, exchange string) (*RabbitMQBroker, error) {
	if exchange == "" {
		exchange = "coppermind.tasks"
	}

	conn, err := amqp.Dial(amqpURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rabbitmq: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to open rabbitmq channel: %w", err)
	}

	// Declare topic exchange
	err = ch.ExchangeDeclare(
		exchange,
		"topic",
		true,  // durable
		false, // auto-deleted
		false, // internal
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("failed to declare exchange: %w", err)
	}

	return &RabbitMQBroker{
		conn:     conn,
		ch:       ch,
		exchange: exchange,
	}, nil
}

// Publish sends a task onto the RabbitMQ exchange with the given routing key (topic).
func (r *RabbitMQBroker) Publish(ctx context.Context, topic string, task *TaskEnvelope) error {
	if task.ID == "" {
		task.ID = generateTaskID()
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}

	body, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to serialize task envelope: %w", err)
	}

	return r.ch.PublishWithContext(ctx,
		r.exchange,
		topic,
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			MessageId:    task.ID,
			Timestamp:    task.CreatedAt,
			Type:         string(task.Type),
			Body:         body,
		},
	)
}

// Subscribe binds a queue to the topic routing key and invokes handler for delivered messages.
func (r *RabbitMQBroker) Subscribe(ctx context.Context, topic string, handler TaskHandler) error {
	// Declare an exclusive or durable queue for this subscriber
	q, err := r.ch.QueueDeclare(
		"",    // random name
		false, // durable
		true,  // delete when unused
		true,  // exclusive
		false, // no-wait
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	err = r.ch.QueueBind(
		q.Name,
		topic,
		r.exchange,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to bind queue to topic: %w", err)
	}

	msgs, err := r.ch.Consume(
		q.Name,
		"",    // consumer tag
		true,  // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to register consumer: %w", err)
	}

	go func() {
		for {
			select {
			case d, ok := <-msgs:
				if !ok {
					return
				}
				var task TaskEnvelope
				if err := json.Unmarshal(d.Body, &task); err == nil {
					_ = handler(ctx, &task)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Close shuts down the RabbitMQ channel and connection.
func (r *RabbitMQBroker) Close() error {
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.isClosed {
		return nil
	}
	r.isClosed = true
	_ = r.ch.Close()
	return r.conn.Close()
}

func generateTaskID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "task_" + hex.EncodeToString(b)
}
