package load

import (
	"encoding/json"
	"errors"

	"github.com/vivekjami/tripwire/internal/groundtruth"
)

// extractEvent pulls the text fragment out of one SSE event payload as UTF-16
// units (lone surrogates preserved so halves split across events rejoin).
// ok=false means the event carries no text (role, finish, [DONE], other types).
func extractEvent(surface string, payload []byte) (units []uint16, ok bool, err error) {
	if string(payload) == "[DONE]" {
		return nil, false, nil
	}
	switch surface {
	case "responses":
		var e struct {
			Type  string          `json:"type"`
			Delta json.RawMessage `json:"delta"`
		}
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, false, err
		}
		if e.Type != "response.output_text.delta" || len(e.Delta) == 0 {
			return nil, false, nil
		}
		u, err := groundtruth.DecodeJSONString(e.Delta)
		return u, err == nil, err
	default:
		var e struct {
			Choices []struct {
				Delta struct {
					Content json.RawMessage `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, false, err
		}
		if len(e.Choices) == 0 || len(e.Choices[0].Delta.Content) == 0 || string(e.Choices[0].Delta.Content) == "null" {
			return nil, false, nil
		}
		u, err := groundtruth.DecodeJSONString(e.Choices[0].Delta.Content)
		return u, err == nil, err
	}
}

// extractNonStream returns the assistant text of a non-streaming response.
func extractNonStream(surface string, body []byte) (string, error) {
	if surface == "responses" {
		var r struct {
			Output []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return "", err
		}
		if len(r.Output) == 0 || len(r.Output[0].Content) == 0 {
			return "", errors.New("no output text")
		}
		return r.Output[0].Content[0].Text, nil
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	if len(r.Choices) == 0 {
		return "", errors.New("no choices")
	}
	return r.Choices[0].Message.Content, nil
}
