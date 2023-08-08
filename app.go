package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var client *mongo.Client
var db *sql.DB
var mackh *keyset.Handle
var aeskh *keyset.Handle
var ad string

func init() {
	ad = "associated data"
	db = initMySQL()
	client = initMongoDB()
	mackh = initMACKeyset()
	aeskh = initAESKeyset()
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Simple Shell")
	fmt.Println("---------------------")
	for c := 0; c == 0; {
		fmt.Print("-> ")
		text, _ := reader.ReadString('\n')
		// convert CRLF to LF
		text = strings.Replace(text, "\n", "", -1)
		args := strings.Split(text, " ")
		if len(args) == 0 {
			fmt.Println("Please provide a valid command!")
			return
		} else {
			switch args[0] {
			case "add":
				switch args[1] {
				case "mysql":
					fmt.Println("Adding email in MySQL database...")
					addProfileMySQL(args[2])
				case "mongodb":
					fmt.Println("Adding email in MongoDB database...")
					addProfileMongoDB(args[2])
				default:
					fmt.Println("Invalid argument for database!")
				}
			case "search":
				switch args[1] {
				case "mysql":
					fmt.Println("Searching in MySQL database...")
					getProfileMySQL(args[2])
				case "mongodb":
					fmt.Println("Searching in MongoDB database...")
					getProfileMongoDB(args[2])
				default:
					fmt.Println("Invalid argument for database!")
				}
			case "exit":
				c = 1
			default:
				fmt.Println("Invalid argument!")
			}
		}
	}
	err := db.Close()
	if err != nil {
		log.Printf("Error %s when closing mysql DB", err)
		panic(err)
	}
}

func initMACKeyset() *keyset.Handle {
	mackh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		log.Printf("Error %s when creating mac keyset handle", err)
	}
	return mackh
}

func initAESKeyset() *keyset.Handle {
	aeskh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Printf("Error %s when creating aead keyset handle", err)
	}
	return aeskh
}

func initMySQL() *sql.DB {
	config := mysql.NewConfig()
	config.User = os.Getenv("MYSQL_USER")
	config.Passwd = os.Getenv("MYSQL_PASSWORD")
	config.Net = "tcp"
	config.Addr = os.Getenv("MYSQL_ADDRESS")
	config.DBName = os.Getenv("MYSQL_DATABASE")

	db, err := sql.Open("mysql", config.FormatDSN())

	if err != nil {
		panic(err)
	}

	err = db.Ping()

	if err != nil {
		panic(err)
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	query := `CREATE TABLE IF NOT EXISTS profile(id int primary key auto_increment, email_enc BLOB, email_hash VARCHAR(200),
        created_at datetime default CURRENT_TIMESTAMP, updated_at datetime default CURRENT_TIMESTAMP, INDEX idx_email_hash (email_hash))`
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		log.Printf("Error %s when creating profile table", err)
		panic(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		log.Printf("Error %s when getting rows affected", err)
		panic(err)
	}
	log.Printf("Rows affected when creating profile table: %d", rows)

	return db
}

func initMongoDB() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))

	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.Ping(ctx, readpref.Primary())

	if err != nil {
		panic(err)
	} else {
		fmt.Println("Connected to MongoDB!")
	}

	return client
}

func addProfileMySQL(email string) {
	email_hash, err := getMAC(email)
	if err != nil {
		log.Printf("Error %s when calculating MAC", err)
		panic(err)
	}

	email_enc, err := encrypt(email)
	if err != nil {
		log.Printf("Error %s when encrypting email", err)
		panic(err)
	}

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()
	query := "INSERT INTO profile(email_enc, email_hash) VALUES (?, ?)"

	res, err := db.ExecContext(ctx, query, email_enc, base64.StdEncoding.EncodeToString([]byte(email_hash)))
	if err != nil {
		log.Printf("Error %s when inserting row into profile table", err)
		panic(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		log.Printf("Error %s when getting rows affected", err)
		panic(err)
	}
	log.Printf("Rows affected when inserting row into profile table: %d", rows)
}

func getProfileMySQL(email string) {
	email_hash, err := getMAC(email)
	if err != nil {
		log.Printf("Error %s when calculating MAC", err)
		panic(err)
	}

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()
	query := `SELECT id FROM profile WHERE email_hash=?`
	rows, err := db.QueryContext(ctx, query, base64.StdEncoding.EncodeToString([]byte(email_hash)))
	if err != nil {
		log.Printf("Error %s when querying data", err)
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			log.Fatal(err)
		}
		log.Printf("Data row = (%d)\n", id)
	}
}

func getMAC(email string) (string, error) {
	m, err := mac.New(mackh)
	if err != nil {
		log.Printf("Error %s when creating MAC primitive", err)
		return "", err
	}

	mac, err := m.ComputeMAC([]byte(email))
	if err != nil {
		log.Printf("Error %s when calculating MAC", err)
		return "", err
	}

	return string(mac[:]), err
}

func encrypt(email string) (string, error) {
	a, err := aead.New(aeskh)
	if err != nil {
		log.Printf("Error %s when creating AEAD primitive", err)
		panic(err)
	}

	ct, err := a.Encrypt([]byte(email), []byte(ad))
	if err != nil {
		log.Printf("Error %s when encrypting email", err)
		panic(err)
	}

	return string(ct[:]), err
}

func addProfileMongoDB(email string) {
	email_hash, err := getMAC(email)
	if err != nil {
		log.Printf("Error %s when calculating MAC", err)
		panic(err)
	}

	email_enc, err := encrypt(email)
	if err != nil {
		log.Printf("Error %s when encrypting email", err)
		panic(err)
	}

	collection := client.Database("users").Collection("profile")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := collection.InsertOne(ctx, bson.M{"email_enc": email_enc, "email_hash": base64.StdEncoding.EncodeToString([]byte(email_hash))})
	if err != nil {
		log.Printf("Error %s when inserting row into profile table", err)
		panic(err)
	}
	id := res.InsertedID
	log.Printf("Inserted a single document: %s", id)
}

func getProfileMongoDB(email string) {
	email_hash, err := getMAC(email)
	if err != nil {
		log.Printf("Error %s when calculating MAC", err)
		panic(err)
	}

	collection := client.Database("users").Collection("profile")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result bson.M
	err = collection.FindOne(ctx, bson.M{"email_hash": base64.StdEncoding.EncodeToString([]byte(email_hash))}).Decode(&result)
	if err != nil {
		log.Printf("Error %s when querying data", err)
		panic(err)
	}
	log.Printf("Found a single document: %+v\n", result)
}
