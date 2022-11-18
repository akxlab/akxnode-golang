package repositories

import (
	"go.mongodb.org/mongo-driver/mongo"
)

type IRepo interface {
	getCollection() *mongo.Collection
}
