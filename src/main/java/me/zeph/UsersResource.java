package me.zeph;

import java.security.MessageDigest;
import java.util.List;
import java.util.regex.Pattern;

import org.jboss.resteasy.reactive.RestHeader;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import me.zeph.database.repositories.UserRepository;
import me.zeph.database.structs.user.User;
import me.zeph.database.structs.user.UserIdentification;
import me.zeph.database.structs.user.UserIdentificationType;
import me.zeph.requests.RegisterRequest;
import me.zeph.responses.LoginResponse;


@Path("/users")
public class UsersResource {

    static final String EMAIL_REGEX = "^[\\w\\-\\.]+@([\\w\\-]+\\.)+[\\w\\-]{2,4}$";
    static final String USERNAME_REGEX = "^[a-zA-Z0-9_]{3,16}$";
    static final Number[] PASSWORD_LENGTH = {8, 64};

    @Inject
    UserRepository userRepository;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<User> getUsers() {
        return userRepository.getUsers();
    }

    @GET
    @Path("/me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response me(
        @RestHeader("Authorization") String token
    ) {
        // Decode the token and validate it
        User user = User.validateJWT(userRepository, token);

        if (user == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Invalid token")
                .build();
        }

        return Response.ok()
            .entity(user)
            .build();
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(
        RegisterRequest loginRequest
    ) {
        UserIdentification usernameIdentification = new UserIdentification(UserIdentificationType.USERNAME, loginRequest.username());
        User user = userRepository.findUser(usernameIdentification);

        if (user == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Invalid username")
                .build();
        }

        // Check password
        byte[] hash = User.hashPassword(loginRequest.password(), user.getSalt());
        if (!MessageDigest.isEqual(hash, user.getPassword())) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Invalid password")
                .build();
        }

        // Authorize the user
        String jwt = user.authorize(userRepository);
        LoginResponse loginResponse = new LoginResponse(user, jwt);

        return Response.ok()
            .entity(loginResponse)
            .build();
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(
        RegisterRequest registerRequest
    ) {
        // Check email format
        Pattern emailPattern = Pattern.compile(EMAIL_REGEX);
        if (!emailPattern.matcher(registerRequest.email()).matches()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid email")
                .build();
        }

        // Check username length and characters
        Pattern usernamePattern = Pattern.compile(USERNAME_REGEX);
        if (!usernamePattern.matcher(registerRequest.username()).matches()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid username")
                .build();
        }

        // Check password length
        if (registerRequest.password().length() < PASSWORD_LENGTH[0].intValue() || registerRequest.password().length() > PASSWORD_LENGTH[1].intValue()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid password")
                .build();
        }

        // Make sure a user with the same email or username doesn't exist
        List<UserIdentification> emailIdentification = List.of(
            new UserIdentification(UserIdentificationType.EMAIL, registerRequest.email()),
            new UserIdentification(UserIdentificationType.USERNAME, registerRequest.username())
        );

        for (UserIdentification identification : emailIdentification) {
            User user = userRepository.findUser(identification);
            if (user != null) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("User already exists")
                    .build();
            }
        }

        // Create the user
        User user = new User(
            registerRequest.email(),
            registerRequest.username(),
            registerRequest.password()
        ); user.save(userRepository);

        return Response.ok()
            .entity(user)
            .build();
    }
}
