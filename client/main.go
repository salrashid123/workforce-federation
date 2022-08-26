package main

import (
	"context"
	"fmt"

	pubsub "cloud.google.com/go/pubsub"
	"google.golang.org/api/iterator"
)

var (
	projectID = "fabled-ray-104117"
)

const ()

func main() {
	ctx := context.Background()
	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		fmt.Printf("pubsub.NewClient: %v", err)
		return
	}
	defer pubsubClient.Close()

	pit := pubsubClient.Topics(ctx)
	for {
		topic, err := pit.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			fmt.Printf("pubssub.Iterating error: %v", err)
			return
		}
		fmt.Printf("Topic Name: %s\n", topic.ID())
	}
}
