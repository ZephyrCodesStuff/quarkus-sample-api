package me.zeph.database.repositories;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import me.zeph.database.structs.user.User;
import me.zeph.database.structs.user.UserException;
import me.zeph.database.structs.user.UserIdentification;

import java.util.ArrayList;
import java.util.List;

import org.bson.conversions.Bson;

@ApplicationScoped
public class UserRepository {
    
    @Inject
    MongoClient mongoClient;

    private MongoDatabase database;
    private MongoCollection<User> collection;

    @PostConstruct
    void setup() {
        database = mongoClient.getDatabase("quarkus");
        collection = database.getCollection("users", User.class);
    }

    public List<User> getUsers() {
        return collection.find().into(new ArrayList<>());
    }

    public User findUser(UserIdentification identification) {
        Bson filter = switch (identification.getType()) {
            case EMAIL -> Filters.eq("email", identification.getValue());
            case USERNAME -> Filters.eq("username", identification.getValue());
            case TOKEN -> Filters.eq("lastToken", identification.getValue());
        };

        User user = collection.find(filter).first();
        return user;
    }

    public void saveUser(User user) throws UserException {
        try {
            collection.insertOne(user);
        } catch (Exception e) {
            throw new UserException("Failed to save user");
        }
    }

    public void updateUser(User user) {
        Bson filter = Filters.eq("email", user.getEmail());
        collection.replaceOne(filter, user);
    }
}
