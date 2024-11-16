package me.zeph.database.structs.user;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.AbstractMap.SimpleEntry;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.mongodb.lang.Nullable;

import lombok.Data;
import lombok.NoArgsConstructor;
import me.zeph.database.repositories.UserRepository;

@Data
@NoArgsConstructor
public class User {
    UserType type;

    String email;
    String username;

    byte[] password;
    byte[] salt;

    @Nullable
    String hwid; // base64 encoded

    Date createdAt;

    @Nullable
    Date expiresAt;

    @Nullable
    String lastToken; // ID of the last JWT created for this user

    public User(String email, String username, String password) {
        this.type = UserType.USER;
        
        this.email = email;
        this.username = username;

        // Generate a random salt
        byte[] salt = new byte[22];
        new java.security.SecureRandom().nextBytes(salt);
        this.salt = salt;

        // Hash the password
        byte[] hash = User.hashPassword(password, salt);
        this.password = hash;

        this.createdAt = new Date();
    }

    /**
     * Check if the user has an active subscription
     * 
     * @return True if the user's current subscription is active (not expired)
     */
    public boolean isActive() {
        if (expiresAt == null) return false;
        return expiresAt.after(new Date());
    }

    /**
     * Update the user in the database
     * 
     * @param userRepository The database to update the user in
     */
    public void update(UserRepository userRepository) {
        userRepository.updateUser(this);
    }

    /**
     * Insert the user into the database
     * 
     * @param userRepository The database to insert the user into
     */
    public void save(UserRepository userRepository) {
        userRepository.saveUser(this);
    }

    /**
     * Generate a JWT token for the user
     * 
     * @return The JWT token
     * @throws UserException If the keys could not be loaded
     */
    public String authorize(UserRepository userRepository) throws UserException {
        SimpleEntry<RSAPublicKey, RSAPrivateKey> keys = null;

        try {
            keys = loadKeys();
        } catch (Exception e) {
            throw new UserException("Failed to load keys: " + e.getMessage());
        }

        RSAPublicKey pubKey = keys.getKey();
        RSAPrivateKey privKey = keys.getValue();
        
        Algorithm algorithm = Algorithm.RSA256(pubKey, (RSAPrivateKey) privKey);
        
        String tokenUUID = UUID.randomUUID().toString();
        String token = JWT.create()
            .withClaim("UUID", tokenUUID)
            .withIssuer("API")
            .sign(algorithm);
        
        this.lastToken = tokenUUID;
        this.update(userRepository);
        
        return token;
    }

    /**
     * Check if a JWT header is valid (prefix and signature) and return the matching user
     * 
     * @param userRepository The database to find the user in
     * @param jwt The JWT header
     * @return The user if the JWT is valid, null otherwise
     * @throws UserException If the keys could not be loaded
     */
    public static User validateJWT(UserRepository userRepository, String jwt) throws UserException {
        // Check if token starts with JWT
        if (!jwt.startsWith("JWT ")) {
            return null;
        }

        jwt = jwt.substring(4);

        SimpleEntry<RSAPublicKey, RSAPrivateKey> keys = null;

        try {
            keys = loadKeys();
        } catch (Exception e) {
            throw new UserException("Failed to load keys: " + e.getMessage());
        }

        RSAPublicKey pubKey = keys.getKey();
        RSAPrivateKey privKey = keys.getValue();
        
        Algorithm algorithm = Algorithm.RSA256(pubKey, (RSAPrivateKey) privKey);
        
        try {
            algorithm.verify(JWT.require(algorithm).build().verify(jwt));
        } catch (SignatureVerificationException e) {
            return null;
        }

        // Get the UUID from the token
        String tokenUUID = JWT.decode(jwt).getClaim("UUID").asString();

        // Find the user with the token
        UserIdentification tokenIdentification = new UserIdentification(UserIdentificationType.TOKEN, tokenUUID);
        User user = userRepository.findUser(tokenIdentification);

        if (user == null) {
            throw new UserException("Invalid token");
        }

        return user;
    }

    /**
     * Load the RSA keys from the files
     * 
     * @return A simple entry containing the public and private keys
     * @throws IOException If the files could not be read
     * @throws InvalidKeySpecException If the keys are invalid
     */
    private static SimpleEntry<RSAPublicKey, RSAPrivateKey> loadKeys() throws IOException, InvalidKeySpecException {
        // Load keys from files
        String privateKeyContent = null;
        String publicKeyContent = null;

        try {
            privateKeyContent = Files.readString(Paths.get(".keys/auth_priv.pem"), StandardCharsets.UTF_8);
            publicKeyContent = Files.readString(Paths.get(".keys/auth_pub.pem"), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UserException("Failed to load keys (IO error)");
        }

        privateKeyContent = privateKeyContent
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END PRIVATE KEY-----", "");

        publicKeyContent = publicKeyContent.toString()
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END PUBLIC KEY-----", "");
        
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);

        // Generate a JWT token
        KeyFactory kf = null;

        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (Exception e) {
            throw new UserException("Failed to load keys (bad algorithm)");
        }

        PrivateKey privKey = null;
        RSAPublicKey pubKey = null;

        try {
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKeyBytes);
            privKey = kf.generatePrivate(keySpecPKCS8);

            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKeyBytes);
            pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        } catch (InvalidKeySpecException e) {
            throw new UserException("Failed to load keys (bad key spec)");
        }

        return new SimpleEntry<>(pubKey, (RSAPrivateKey) privKey);
    }

    /**
     * Fetch a user from the database and validate the password
     * 
     * @param userRepository The database to find the user in
     * @param username The username of the user
     * @param password The password of the user
     * @return The user, if the password is correct; null otherwise
     * @throws UserException If the user is not found or the password is incorrect
     */
    public static User resolve(UserRepository userRepository, String username, String password) throws UserException {
        UserIdentification identification = new UserIdentification(UserIdentificationType.USERNAME, username);
        User user = userRepository.findUser(identification);

        if (user == null) {
            throw new UserException("User not found");
        }

        // If the password is incorrect, throw an exception
        byte[] hash = User.hashPassword(password, user.getSalt());
        if (!MessageDigest.isEqual(hash, user.getPassword())) {
            throw new UserException("Invalid password");
        }

        return user;
    }

    /**
     * Hash a password using Argon2 and a salt
     * 
     * @param password The password to hash
     * @param salt The salt to use
     * @return The resulting hash
     */
    public static byte[] hashPassword(String password, byte[] salt) {
        // Create an instance of Argon2 with the parameters
        int iterations = 2;
        int memLimit = 66536;
        int hashLength = 32;
        int parallelism = 1;
            
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memLimit)
            .withParallelism(parallelism)
            .withSalt(salt);

        Argon2BytesGenerator verifier = new Argon2BytesGenerator();
        verifier.init(builder.build());
        
        // Generate the hash of the incoming password
        byte[] generatedHash = new byte[hashLength];
        verifier.generateBytes(password.getBytes(StandardCharsets.UTF_8), generatedHash, 0, generatedHash.length);

        return generatedHash;
    }
}