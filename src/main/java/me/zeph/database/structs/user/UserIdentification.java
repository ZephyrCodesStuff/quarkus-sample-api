package me.zeph.database.structs.user;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Represents a way to identify a user in the database.
 */
@Getter
@AllArgsConstructor
public class UserIdentification {
    UserIdentificationType type;
    String value;
}