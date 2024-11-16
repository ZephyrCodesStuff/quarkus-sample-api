package me.zeph.database.structs.user;

/**
 * Exception thrown when an error occurs while interacting with the user database.
 */
public class UserException extends RuntimeException {
    public UserException(String message) {
        super(message);
    }
}
