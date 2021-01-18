package commands

import (
	"reflect"
	"testing"
)

func TestAppendIfNotExists(t *testing.T) {
	type args struct {
		currentItems []interface{}
		newItem      string
	}
	tests := []struct {
		name string
		args args
		want []interface{}
	}{
		{
			"append",
			args{currentItems: []interface{}{"a"}, newItem: "b"},
			[]interface{}{"a", "b"},
		},
		{
			"skip",
			args{currentItems: []interface{}{"a"}, newItem: "a"},
			[]interface{}{"a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appendIfNotExists(tt.args.currentItems, tt.args.newItem); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("appendIfNotExists() = %v, want %v", got, tt.want)
			}
		})
	}
}
