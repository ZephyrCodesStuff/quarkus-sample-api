package me.zeph.database.structs.user;

/**
 * Enum of the different types of users.
 * 
 * Admin users are able to perform administrative tasks,
 * while regular users can only perform basic tasks such as
 * logging in and checking their own profile.
 */
public enum UserType {
    ADMIN,
    USER
}