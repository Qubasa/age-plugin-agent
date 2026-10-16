package main

import "testing"

func TestParseStateMachine(t *testing.T) {
	tests := []struct {
		args    []string
		want    string
		wantErr bool
	}{
		{args: []string{"--age-plugin=identity-v1"}, want: "identity-v1"},
		{args: []string{"--age-plugin=recipient-v1"}, want: "recipient-v1"},
		{args: []string{"--age-plugin", "identity-v1"}, want: "identity-v1"},
		{args: nil, wantErr: true},
		{args: []string{"--age-plugin="}, wantErr: true},
		{args: []string{"--age-plugin=keygen-v1"}, wantErr: true},
		{args: []string{"--age-plugin=identity-v1", "extra"}, wantErr: true},
		{args: []string{"--generate"}, wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseStateMachine(tt.args)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseStateMachine(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseStateMachine(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}
