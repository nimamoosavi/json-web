package com.nicico.cost.jsonweb.service.token.impl;

import com.nicico.cost.framework.domain.dto.BaseDTO;
import com.nicico.cost.framework.enums.exception.ExceptionEnum;
import com.nicico.cost.framework.packages.json.web.token.view.JwtObjReqVM;
import com.nicico.cost.framework.service.GeneralResponse;
import com.nicico.cost.framework.service.exception.ApplicationException;
import com.nicico.cost.jsonweb.service.token.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final ApplicationException applicationException;

    @Value("${json.web.toke.secretKey}")
    private String secretAppKeys;


    public BaseDTO<String> generateJwt(JwtObjReqVM jwtObjReqVM, String secretKey) {
        Claims claims = Jwts.claims();
        claims.setExpiration(jwtObjReqVM.getExp());
        claims.setId(jwtObjReqVM.getJti());
        claims.setSubject(jwtObjReqVM.getSubject());
        claims.setAudience(jwtObjReqVM.getAud());
        claims.setIssuedAt(jwtObjReqVM.getIat());
        claims.setNotBefore(jwtObjReqVM.getNbf());
        claims.setId(jwtObjReqVM.getJti());
        claims.setIssuer(jwtObjReqVM.getIss());
        claims.putAll(jwtObjReqVM.getCustoms());
        String compact = Jwts.builder().addClaims(claims).signWith(SignatureAlgorithm.HS512, secretKey).compact();
        return GeneralResponse.successCustomResponse(compact);
    }

    public BaseDTO<String> generateJwt(JwtObjReqVM jwtObjReqVM) {
        Claims claims = Jwts.claims();
        claims.setExpiration(jwtObjReqVM.getExp());
        claims.setId(jwtObjReqVM.getJti());
        claims.setSubject(jwtObjReqVM.getSubject());
        claims.setAudience(jwtObjReqVM.getAud());
        claims.setIssuedAt(jwtObjReqVM.getIat());
        claims.setNotBefore(jwtObjReqVM.getNbf());
        claims.setId(jwtObjReqVM.getJti());
        claims.setIssuer(jwtObjReqVM.getIss());
        claims.putAll(jwtObjReqVM.getCustoms());
        String compact = Jwts.builder().addClaims(claims).signWith(SignatureAlgorithm.HS512, secretAppKeys).compact();
        return GeneralResponse.successCustomResponse(compact);
    }

    public BaseDTO<Boolean> isTokenWithoutCheckExpireTime(String jwt, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt);
            return GeneralResponse.successCustomResponse(true);
        } catch (Exception e) {
            return GeneralResponse.successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValid(String jwt, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(true);
        } catch (Exception e) {
            return GeneralResponse.successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValidWithoutCheckExpireTime(String jwt) {
        try {
            Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt);
            return GeneralResponse.successCustomResponse(true);
        } catch (Exception e) {
            return GeneralResponse.successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValid(String jwt) {
        try {
            Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(true);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBodyWithoutCheckExpireTime(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            return GeneralResponse.successCustomResponse(e.getClaims());
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBody(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBodyWithoutCheckExpireTime(String jwt, String secretKey) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            return GeneralResponse.successCustomResponse(e.getClaims());
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBody(String jwt, String secretKey) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParam(String jwt, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims.get(paramName, tClass));
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }


    public <R> BaseDTO<R> getJwtParam(Claims claims, String paramName, Class<R> tClass) {
        try {
            return GeneralResponse.successCustomResponse(claims.get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Object> getJwtParam(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretAppKeys).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParamWithoutCheckExpireTime(String jwt, String secretKey, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims.get(paramName, tClass));
        } catch (ExpiredJwtException e) {
            return GeneralResponse.successCustomResponse(e.getClaims().get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParam(String jwt, String secretKey, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return GeneralResponse.successCustomResponse(claims.get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<String> hash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            String hashResult = Base64.getEncoder().encodeToString(hash);
            return GeneralResponse.successCustomResponse(hashResult);
        } catch (Exception e) {
            throw applicationException.createApplicationException(ExceptionEnum.INTERNAL_SERVER, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
