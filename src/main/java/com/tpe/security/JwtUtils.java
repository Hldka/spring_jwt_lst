package com.tpe.security;

import com.tpe.security.service.*;
import io.jsonwebtoken.*;
import org.springframework.security.core.*;
import org.springframework.stereotype.*;

import java.util.*;

@Component
public class JwtUtils {
    // 1 : JWT generate
    // 2: JWT valide
    // 3 : JWT --> userName
    private String jwtSecret = "sboot";// istedigimiz seyi yazabiliriz

    private  long jwtExpirationMs = 86400000;   // 24*60*60*1000 birgün diyeceksek

    // !!! ************ GENERATE TOKEN *****************
    public String generateToken(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();// anlik olarak login islemi gerceklesen user'a ulastim

        return Jwts.builder().// jw tokene'i üretir
                setSubject(userDetails.getUsername()).//jwtokeniniz username'den üretilir
                setIssuedAt(new Date()).// jwtoken ne zaman üretildi
                setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).// jwt tokeni ne zaman bitecek(new ne zama olacagini ve 24 saat olacagini ekeldeim)
                signWith(SignatureAlgorithm.HS512, jwtSecret).// sifreleme algoritmalari
                compact();
    }

    // !!! ****************** VALIDATE TOKEN ***************************
    public boolean validateToken(String token){

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false ;
    }

    // !!! ********** JWT tokenden userName'i alalım ************
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().//
                setSigningKey(jwtSecret).// ne ile sifreledim
                parseClaimsJws(token).
                getBody().
                getSubject();
        // ya password ile username ie yapabilirim ,user name uniq onun icin ulasmam daha kolay
        //filter kisminda jwt generate ve jwt validate yaptik
    }

}
