### this interface used for working with json web token and implemented in json web library

### Requirements
The library works with Java 8+, ladder Core 1.0.1+ and repository implementation such as
mongo client project , jdbc client project or micro client or your implementation

## [Core](https://github.com/nimamoosavi/core/wiki)


## Structure

![json-web Diagram](https://github.com/nimamoosavi/json-web/wiki/images/jwt.jpeg)


## methode
BaseDTO<String> generateJwt(JwtObjReqVM jwtObjReqVM, String secretKey, SignatureAlgorithm signatureAlgorithm);
> create a jwt with your secretKey for sign json web token

BaseDTO<String> generateJwt(JwtObjReqVM jwtObjReqVM);
> create a jwt with default secret Key uoy can change it by change your properties json.web.toke.secretKey=123

BaseDTO<Boolean> isTokenWithoutCheckExpireTime(String jwt, String secretKey);
>this method used for validate a jwt token without check expire time just check jwt signing

BaseDTO<Boolean> isValid(String jwt, String secretKey);
>this method validate jwt and return a boolean

BaseDTO<Boolean> isValidWithoutCheckExpireTime(String jwt);
>this method validate jwt and return a boolean

BaseDTO<Boolean> isValid(String jwt);
> jwt is your input jwt
>
> return Boolean for process
>
> secret key is a default field in your application properties

BaseDTO<Claims> getJwtBodyWithoutCheckExpireTime(String jwt);
> jwt is your input jwt
>
> return object of claims that is your json body
>
> secret key is a default field in your application properties
>
> this method not validate expireTime

< R > BaseDTO< R > getJwtParam(String jwt, String paramName, Class< R > tClass);
> jwt       is your input jwt
>
> paramName is your key that you want fetch from claims
>
> tClass is object that you want cast to it
>
> < R > the class type
