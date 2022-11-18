package models

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"time"

	"akxsystem/src/repositories"
)

type User struct {
	AKXID   string `bson:"akx_id"`
	Address string `bson:"address"`
}

type IUserRepository interface {
	Get(AKXID string) (*User, bool)
	Exists(AKXID string) (exists bool)
	GetByAddress(address string) (*User, bool)
	HasAKXID(address string) (hasOne bool)
	GetByNamedAlias(namedAlias string) (*User, bool)
}

type UserRepository struct {
	repositories.IRepo
	IUserRepository
}

type UserMetas struct {
	AKXID      string `bson:"akx_id"`
	NamedAlias string `bson:"user_name"`
	TokenID    uint   `bson:"token_id"`
	AvatarURI  string `bson:"avatar_uri"`
}

func (ur UserRepository) getCollection() *mongo.Collection {
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI("mongodb+srv://akx3testnet:" + os.Getenv("ATLAS_TESTNET_PWD") + "@akxserverless.0msbo.mongodb.net/?retryWrites=true&w=majority").
		SetServerAPIOptions(serverAPIOptions)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("testnet_photon").Collection("users")
}

func (ur UserRepository) Get(AKXID string) (*User, bool) {
	coll := ur.getCollection()
	filter := bson.M{"AKXID": AKXID}
	var result User
	err := coll.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &User{}, false
		}
		log.Fatal(err)
	}
	return &result, true
}

func (ur UserRepository) Exists(AKXID string) (exists bool) {
	_, exists = ur.Get(AKXID)
	return
}

func (ur UserRepository) GetByAddress(address string) (*User, bool) {
	coll := ur.getCollection()
	filter := bson.M{"address": address}
	var result User
	err := coll.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &User{}, false
		}
		log.Fatal(err)
	}
	return &result, true
}

func (ur UserRepository) HasAKXID(address string) (hasOne bool) {
	_, hasOne = ur.GetByAddress(address)
	return
}

func (ur UserRepository) GetByNamedAlias(namedAlias string) (*User, bool) {
	var um UserMetas
	coll := um.getCollection()
	filter := bson.M{"user_name": namedAlias}
	var result UserMetas
	err := coll.FindOne(context.TODO(), filter).Decode(&result)
	usermetas := &result
	user, _ := ur.Get(usermetas.AKXID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &User{}, false
		}
		log.Fatal(err)
	}
	return user, true

}

func (um UserMetas) Get(AKXID string) (*UserMetas, bool) {
	coll := um.getCollection()
	filter := bson.M{"AKXID": AKXID}
	var result UserMetas
	err := coll.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &UserMetas{}, false
		}
		log.Fatal(err)
	}
	return &result, true
}

func (um UserMetas) getCollection() *mongo.Collection {
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI("mongodb+srv://akx3testnet:" + os.Getenv("ATLAS_TESTNET_PWD") + "@akxserverless.0msbo.mongodb.net/?retryWrites=true&w=majority").
		SetServerAPIOptions(serverAPIOptions)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("testnet_photon").Collection("metas")
}

func (ur UserRepository) NameExists(name string) (exists bool) {
	_, exists = ur.GetByNamedAlias(name)
	return
}

func (um UserMetas) GetAvatarURI(AKXID string) (avatar_uri string) {
	metas, _ := um.Get(AKXID)
	avatar_uri = metas.AvatarURI
	return
}

func (um UserMetas) GetTokenID(AKXID string) (tokenId uint) {
	metas, _ := um.Get(AKXID)
	tokenId = metas.TokenID
	return
}
