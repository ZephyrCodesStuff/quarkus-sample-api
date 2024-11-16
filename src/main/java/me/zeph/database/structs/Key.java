package me.zeph.database.structs;

import java.util.Date;

import com.mongodb.lang.Nullable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a key that can be redeemed to extend a user's subscription.
 */
@Data
@NoArgsConstructor @AllArgsConstructor
public class Key {
    String name;
    Number days;

    @Nullable
    Date usedAt;

    @Nullable
    String usedBy;
}