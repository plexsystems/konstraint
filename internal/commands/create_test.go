package commands

import (
	"reflect"
	"testing"
)

func TestAppendIfNotExists(t *testing.T) {
	type args struct {
		currentItems []string
		newItem      string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"append",
			args{currentItems: []string{"a"}, newItem: "b"},
			[]string{"a", "b"},
		},
		{
			"skip",
			args{currentItems: []string{"a"}, newItem: "a"},
			[]string{"a"},
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

func TestToInterfaceSlice(t *testing.T) {
	type args struct {
		input []string
	}
	tests := []struct {
		name string
		args args
		want []interface{}
	}{
		{
			"empty",
			args{[]string{}},
			[]interface{}{},
		},
		{
			"valid",
			args{[]string{"a", "b"}},
			[]interface{}{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toInterfaceSlice(tt.args.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toInterfaceSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
