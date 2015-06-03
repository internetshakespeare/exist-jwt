package ca.terpstra.max.exist_jwt;

import org.exist.dom.QName;
import org.exist.xquery.ErrorCodes;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.UnresolvableKeyException;
import org.jose4j.lang.JoseException;

/**
 * XQuery error codes for JwtModule
 */
public class JwtErrorCode extends ErrorCodes.ErrorCode {

    public JwtErrorCode(QName name, String desc) {
        super(name, desc);
    }

    public static final JwtErrorCode INVALID_ERR = new JwtErrorCode(
        new QName("INVALID_ERR", JwtModule.NAMESPACE_URI, JwtModule.PREFIX),
        "Invalid or unsupported JWT"
    );
    public static final JwtErrorCode NO_KEY_ERR = new JwtErrorCode(
        new QName("NO_KEY_ERR", JwtModule.NAMESPACE_URI, JwtModule.PREFIX),
        "No appropriate key found to verify JWT"
    );
    public static final JwtErrorCode FORGERY_ERR = new JwtErrorCode(
        new QName("FORGERY_ERR", JwtModule.NAMESPACE_URI, JwtModule.PREFIX),
        "Incorrect JWT signature"
    );
    public static final JwtErrorCode UNKNOWN_ERR = new JwtErrorCode(
        new QName("UNKNOWN_ERR", JwtModule.NAMESPACE_URI, JwtModule.PREFIX),
        "Unexpected server error while parsing/verifying JWT"
    );

    public static JwtErrorCode errorFor(Exception e) {
        if (e instanceof MalformedClaimException) {
            return INVALID_ERR;
        }
        else if (e instanceof InvalidJwtSignatureException) {
            return FORGERY_ERR;
        }
        else if (e instanceof InvalidJwtException) {
            return INVALID_ERR;
        }
        else if (e instanceof UnresolvableKeyException) {
            return NO_KEY_ERR;
        }
        else if (e instanceof JoseException) {
            return INVALID_ERR;
        } 
        else {
            return UNKNOWN_ERR;
        }
    }

}
