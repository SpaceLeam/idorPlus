package fuzzer

import (
	"sync"

	"idorplus/pkg/client"
	"idorplus/pkg/detector"

	"github.com/go-resty/resty/v2"
)

type FuzzEngine struct {
	Client   *client.SmartClient
	Workers  int
	Queue    chan *FuzzJob
	Results  chan *FuzzResult
	wg       sync.WaitGroup
	Detector *detector.IDORDetector
}

type FuzzJob struct {
	URL     string
	Method  string
	Payload string
	Headers map[string]string
}

type FuzzResult struct {
	Job          *FuzzJob
	Response     *resty.Response
	IsVulnerable bool
	Evidence     string
}

func NewFuzzEngine(c *client.SmartClient, workers int, detector *detector.IDORDetector) *FuzzEngine {
	return &FuzzEngine{
		Client:   c,
		Workers:  workers,
		Queue:    make(chan *FuzzJob, workers*10),
		Results:  make(chan *FuzzResult, workers*10),
		Detector: detector,
	}
}

func (fe *FuzzEngine) Start() {
	for i := 0; i < fe.Workers; i++ {
		fe.wg.Add(1)
		go fe.worker()
	}
}

func (fe *FuzzEngine) Stop() {
	close(fe.Queue)
	fe.wg.Wait()
	close(fe.Results)
}

func (fe *FuzzEngine) worker() {
	defer fe.wg.Done()

	for job := range fe.Queue {
		result := fe.processJob(job)
		fe.Results <- result
	}
}

func (fe *FuzzEngine) processJob(job *FuzzJob) *FuzzResult {
	req := fe.Client.Request()

	// Add custom headers
	for k, v := range job.Headers {
		req.SetHeader(k, v)
	}

	// Execute request based on method
	var resp *resty.Response
	var err error

	switch job.Method {
	case "GET":
		resp, err = req.Get(job.URL)
	case "POST":
		resp, err = req.Post(job.URL)
	case "PUT":
		resp, err = req.Put(job.URL)
	case "DELETE":
		resp, err = req.Delete(job.URL)
	case "PATCH":
		resp, err = req.Patch(job.URL)
	default:
		resp, err = req.Get(job.URL)
	}

	if err != nil {
		return &FuzzResult{Job: job, IsVulnerable: false}
	}

	// Detect IDOR
	isVuln := fe.Detector.Detect(resp)

	return &FuzzResult{
		Job:          job,
		Response:     resp,
		IsVulnerable: isVuln,
		Evidence:     resp.String(), // Simplified evidence
	}
}
