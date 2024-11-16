package me.zeph.responses;

import me.zeph.database.structs.user.User;

public record LoginResponse(User user, String jwt) { }