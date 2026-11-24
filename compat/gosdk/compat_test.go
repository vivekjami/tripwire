// Compatibility check with a real, third-party OpenAI client library
// (github.com/sashabaranov/go-openai) pointed at a running Tripwire gateway.
//
//	TW_GATEWAY_URL=http://127.0.0.1:18080 TW_API_KEY=tw_... go test ./...
package gosdk

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

func client(t *testing.T) *openai.Client {
	url, key := os.Getenv("TW_GATEWAY_URL"), os.Getenv("TW_API_KEY")
	if url == "" || key == "" {
		t.Skip("set TW_GATEWAY_URL and TW_API_KEY (scripts/compat.sh does this)")
	}
	cfg := openai.DefaultConfig(key)
	cfg.BaseURL = strings.TrimRight(url, "/") + "/v1"
	return openai.NewClientWithConfig(cfg)
}

func TestNonStream(t *testing.T) {
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "gpt-4o",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content == "" || resp.Choices[0].Message.Role != "assistant" {
		t.Fatalf("%+v", resp)
	}
}

func TestStream(t *testing.T) {
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := c.CreateChatCompletionStream(ctx, openai.ChatCompletionRequest{Model: "gpt-4o", Stream: true,
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var sb strings.Builder
	n := 0
	for {
		r, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("stream error after %d events: %v", n, err)
		}
		n++
		if len(r.Choices) > 0 {
			sb.WriteString(r.Choices[0].Delta.Content)
		}
	}
	if n < 3 || sb.Len() == 0 {
		t.Fatalf("%d events, %q", n, sb.String())
	}
}

func TestModelsList(t *testing.T) {
	c := client(t)
	ms, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms.Models {
		if !strings.HasPrefix(m.ID, "gpt-") {
			t.Errorf("model %q is outside the agent's scope but was listed", m.ID)
		}
	}
}

func TestAuthFailureIsAnAPIError(t *testing.T) {
	url := os.Getenv("TW_GATEWAY_URL")
	if url == "" {
		t.Skip("no gateway")
	}
	cfg := openai.DefaultConfig("tw_wrong_" + strings.Repeat("a", 43))
	cfg.BaseURL = strings.TrimRight(url, "/") + "/v1"
	_, err := openai.NewClientWithConfig(cfg).CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{Model: "gpt-4o",
		Messages: []openai.ChatCompletionMessage{{Role: "user", Content: "x"}}})
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatusCode != 401 {
		t.Fatalf("want a 401 *openai.APIError, got %T %v", err, err)
	}
}

func TestUnknownModelIs404(t *testing.T) {
	c := client(t)
	_, err := c.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{Model: "claude-secret",
		Messages: []openai.ChatCompletionMessage{{Role: "user", Content: "x"}}})
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatusCode != 404 {
		t.Fatalf("want 404, got %T %v", err, err)
	}
}
