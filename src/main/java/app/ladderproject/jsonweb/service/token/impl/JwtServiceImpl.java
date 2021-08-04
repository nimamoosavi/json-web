package app.ladderproject.jsonweb.service.token.impl;

import app.ladderproject.core.domain.dto.BaseDTO;
import app.ladderproject.core.packages.json.web.token.view.JwtObjReqVM;
import app.ladderproject.core.service.exception.ApplicationException;
import app.ladderproject.core.service.exception.ServiceException;
import app.ladderproject.jsonweb.service.config.JsonWebConfig;
import app.ladderproject.jsonweb.service.enums.JsonWebException;
import app.ladderproject.jsonweb.service.token.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static app.ladderproject.core.enums.exception.ExceptionEnum.INTERNAL_SERVER;
import static app.ladderproject.core.service.GeneralResponse.successCustomResponse;

@Component
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final ApplicationException<ServiceException> applicationException;


    public BaseDTO<String> generateJwt(JwtObjReqVM jwtObjReqVM, String secretKey, SignatureAlgorithm signatureAlgorithm) {
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
        String compact = Jwts.builder().addClaims(claims).signWith(signatureAlgorithm, secretKey).compact();
        return successCustomResponse(compact);
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
        String compact = Jwts.builder().addClaims(claims).signWith(JsonWebConfig.signatureAlgorithm, JsonWebConfig.secretKey).compact();
        return successCustomResponse(compact);
    }

    public BaseDTO<Boolean> isTokenWithoutCheckExpireTime(String jwt, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt);
            return successCustomResponse(true);
        } catch (Exception e) {
            return successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValid(String jwt, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(true);
        } catch (Exception e) {
            return successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValidWithoutCheckExpireTime(String jwt) {
        try {
            Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt);
            return successCustomResponse(true);
        } catch (Exception e) {
            return successCustomResponse(false);
        }
    }

    public BaseDTO<Boolean> isValid(String jwt) {
        try {
            Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(true);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBodyWithoutCheckExpireTime(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            return successCustomResponse(e.getClaims());
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBody(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBodyWithoutCheckExpireTime(String jwt, String secretKey) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            return successCustomResponse(e.getClaims());
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Claims> getJwtBody(String jwt, String secretKey) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims);
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParam(String jwt, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims.get(paramName, tClass));
        } catch (ExpiredJwtException e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_EXPIRED, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }


    public <R> BaseDTO<R> getJwtParam(Claims claims, String paramName, Class<R> tClass) {
        try {
            return successCustomResponse(claims.get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<Object> getJwtParam(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(JsonWebConfig.secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims);
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParamWithoutCheckExpireTime(String jwt, String secretKey, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims.get(paramName, tClass));
        } catch (ExpiredJwtException e) {
            return successCustomResponse(e.getClaims().get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public <R> BaseDTO<R> getJwtParam(String jwt, String secretKey, String paramName, Class<R> tClass) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody();
            return successCustomResponse(claims.get(paramName, tClass));
        } catch (Exception e) {
            throw applicationException.createApplicationException(JsonWebException.JWT_TOKEN_INVALID, HttpStatus.BAD_REQUEST);
        }
    }

    public BaseDTO<String> hash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            String hashResult = Base64.getEncoder().encodeToString(hash);
            return successCustomResponse(hashResult);
        } catch (Exception e) {
            throw applicationException.createApplicationException(INTERNAL_SERVER, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
