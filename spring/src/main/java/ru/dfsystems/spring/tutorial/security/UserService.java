package ru.dfsystems.spring.tutorial.security;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import ru.dfsystems.spring.tutorial.generated.tables.daos.AppUserDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.AppUser;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

import static java.security.MessageDigest.getInstance;
import static ru.dfsystems.spring.tutorial.generated.tables.AppUser.APP_USER;

@Service
@AllArgsConstructor
public class UserService {

    private AppUserDao appUserDao;
    private MappingService mappingService;
    private UserContext userContext;

    public AppUser getUserByLogin(String login){
        return appUserDao.fetchOptional(APP_USER.LOGIN, login)
                .orElse(null);
    }

    public boolean checkPassword(String login, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        AppUser user = getUserByLogin(login);
        if (user == null) {
            return false;
        }

        // ДЗ Добавить соль к паролю. Соль хранить в application.yml
//        String md5Hex = DigestUtils.md5DigestAsHex(password.getBytes())
//                .toUpperCase();

        String sha256 = getPassword(password).toUpperCase();

        return sha256.equals(user.getPasswordHash());
    }

    public UserDto getCurrentUser() {
        return mappingService.map(userContext.getUser(), UserDto.class);
    }

    public void login(String login) {
        AppUser user = getUserByLogin(login);
        user.setLastLoginDate(LocalDateTime.now());
        user.setIsActive(true);

        appUserDao.update(user);
    }

    public static String getPassword(String password) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        MessageDigest messageDigest = getInstance("SHA-256");
        messageDigest.update(password.getBytes("UTF-8"));

        byte[] digest = messageDigest.digest();

        return String.format("%064x", new BigInteger(1, digest));
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        System.out.println( getPassword("ctumso12").toUpperCase());
    }

    public void logout() {
        AppUser user = getUserByLogin(getCurrentUser().getLogin());
        user.setIsActive(false);
        appUserDao.update(user);
    }

}
