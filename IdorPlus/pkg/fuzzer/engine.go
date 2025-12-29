package fuzzer

import (
	"context"
	"sync"
	"time"

	"idorplus/pkg/client"
	"idorplus/pkg/detector"

	"github.com/go-resty/resty/v2"
)

// FuzzJob represents a single fuzzing task
type FuzzJob struct {
	ID      int
	URL     string
	Method  string
	Payload string
	Headers map[string]string
	Body    string
	Session string
}

// FuzzResult represents the result of a fuzzing task
type FuzzResult struct {
	Job          *FuzzJob
	Response     *resty.Response
	StatusCode   int
	ContentLen   int
	IsVulnerable bool
	Evidence     string
	Error        error
	Duration     time.Duration
}

// FuzzEngine is a production-grade fuzzing engine with proper concurrency handling
type FuzzEngine struct {
	Client     *client.SmartClient
	Workers    int
	Queue      chan *FuzzJob
	Results    chan *FuzzResult
	Detector   *detector.IDORDetector
	Stats      *Stats
	MaxRetries int

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	mu      sync.Mutex
}

// NewFuzzEngine creates a new fuzzing engine
func NewFuzzEngine(c *client.SmartClient, workers int, det *detector.IDORDetector) *FuzzEngine {
	ctx, cancel := context.WithCancel(context.Background())

	// Buffer channels appropriately
	queueSize := workers * 10
	if queueSize < 100 {
		queueSize = 100
	}

	return &FuzzEngine{
		Client:     c,
		Workers:    workers,
		Queue:      make(chan *FuzzJob, queueSize),
		Results:    make(chan *FuzzResult, queueSize),
		Detector:   det,
		Stats:      NewStats(),
		MaxRetries: 3,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches worker goroutines
func (fe *FuzzEngine) Start() {
	fe.mu.Lock()
	if fe.started {
		fe.mu.Unlock()
		return
	}
	fe.started = true
	fe.mu.Unlock()

	for i := 0; i < fe.Workers; i++ {
		fe.wg.Add(1)
		go fe.worker(i)
	}
}

// Stop gracefully stops the engine
func (fe *FuzzEngine) Stop() {
	fe.cancel() // Signal all workers to stop

	// Close queue to signal workers
	fe.mu.Lock()
	if fe.started {
		close(fe.Queue)
	}
	fe.mu.Unlock()

	// Wait for workers to finish
	fe.wg.Wait()

	// Drain any remaining results to prevent blocking
	go func() {
		for range fe.Results {
			// Discard remaining results
		}
	}()

	// Close results channel
	close(fe.Results)
}

// Cancel immediately cancels all operations
func (fe *FuzzEngine) Cancel() {
	fe.cancel()
}

// GetContext returns the engine's context
func (fe *FuzzEngine) GetContext() context.Context {
	return fe.ctx
}

// Submit adds a job to the queue
func (fe *FuzzEngine) Submit(job *FuzzJob) bool {
	select {
	case <-fe.ctx.Done():
		return false
	case fe.Queue <- job:
		return true
	}
}

// CloseQueue closes the job queue (call after submitting all jobs)
func (fe *FuzzEngine) CloseQueue() {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	close(fe.Queue)
}

// worker processes jobs from the queue
func (fe *FuzzEngine) worker(id int) {
	defer fe.wg.Done()

	for {
		select {
		case <-fe.ctx.Done():
			return
		case job, ok := <-fe.Queue:
			if !ok {
				return
			}
			result := fe.processJob(job)

			// Send result, but check for cancellation
			select {
			case <-fe.ctx.Done():
				return
			case fe.Results <- result:
			}
		}
	}
}

// processJob executes a single fuzzing job with retry logic
func (fe *FuzzEngine) processJob(job *FuzzJob) *FuzzResult {
	startTime := time.Now()
	var resp *resty.Response
	var err error

	// Retry loop with exponential backoff
	for attempt := 0; attempt <= fe.MaxRetries; attempt++ {
		// Check for cancellation
		select {
		case <-fe.ctx.Done():
			return &FuzzResult{
				Job:   job,
				Error: fe.ctx.Err(),
			}
		default:
		}

		// Get request with rate limiting
		req, reqErr := fe.Client.RequestWithRateLimit(fe.ctx)
		if reqErr != nil {
			if attempt == fe.MaxRetries {
				fe.Stats.IncrementTotal()
				fe.Stats.IncrementFailed()
				return &FuzzResult{
					Job:   job,
					Error: reqErr,
				}
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}

		// Add custom headers
		for k, v := range job.Headers {
			req.SetHeader(k, v)
		}

		// Add session cookies if specified
		if job.Session != "" {
			session := fe.Client.GetSessionManager().GetSession(job.Session)
			if session != nil {
				for _, cookie := range session.Cookies {
					req.SetCookie(cookie)
				}
			}
		}

		// Add body if present
		if job.Body != "" {
			req.SetBody(job.Body)
		}

		// Execute request based on method
		switch job.Method {
		case "POST":
			resp, err = req.Post(job.URL)
		case "PUT":
			resp, err = req.Put(job.URL)
		case "DELETE":
			resp, err = req.Delete(job.URL)
		case "PATCH":
			resp, err = req.Patch(job.URL)
		case "HEAD":
			resp, err = req.Head(job.URL)
		case "OPTIONS":
			resp, err = req.Options(job.URL)
		default:
			resp, err = req.Get(job.URL)
		}

		if err == nil {
			break
		}

		// Exponential backoff for retries
		if attempt < fe.MaxRetries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	fe.Stats.IncrementTotal()

	if err != nil {
		fe.Stats.IncrementFailed()
		return &FuzzResult{
			Job:      job,
			Error:    err,
			Duration: time.Since(startTime),
		}
	}

	fe.Stats.IncrementSuccess()

	// Detect vulnerability
	isVuln := false
	if fe.Detector != nil {
		isVuln = fe.Detector.Detect(resp)
	}

	if isVuln {
		fe.Stats.IncrementVuln()
	}

	return &FuzzResult{
		Job:          job,
		Response:     resp,
		StatusCode:   resp.StatusCode(),
		ContentLen:   len(resp.Body()),
		IsVulnerable: isVuln,
		Evidence:     string(resp.Body()),
		Duration:     time.Since(startTime),
	}
}

// WaitForCompletion waits for all results to be processed
func (fe *FuzzEngine) WaitForCompletion() {
	fe.wg.Wait()
}

// WaitAndClose waits for all workers to finish and closes the Results channel
// This should be called after CloseQueue() to properly signal completion
func (fe *FuzzEngine) WaitAndClose() {
	fe.wg.Wait()
	close(fe.Results)
}
