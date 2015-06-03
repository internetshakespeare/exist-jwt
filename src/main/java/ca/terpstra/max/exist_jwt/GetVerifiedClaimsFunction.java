package ca.terpstra.max.exist_jwt;

import org.exist.dom.QName;
import org.exist.xquery.*;
import org.exist.xquery.value.*;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.resolvers.*;
import org.jose4j.jwt.consumer.*;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import java.util.Vector;

/**
 * Parses and verifies a JWT, and returns its JSON payload.
 * Part of the JwtModule.
 */
public class GetVerifiedClaimsFunction extends BasicFunction {

    public static final FunctionDef DEFINITION = new FunctionDef(
        new FunctionSignature(
            new QName("get-verified-claims", JwtModule.NAMESPACE_URI, JwtModule.PREFIX),
            "Verfiy the given JWT, and return its JSON payload as a map()",
            new SequenceType[] {
                new FunctionParameterSequenceType(
                    "jwt", Type.STRING, Cardinality.EXACTLY_ONE,
                    "compact JWT"
                ),
                new FunctionParameterSequenceType(
                    "key-callback", Type.FUNCTION_REFERENCE, Cardinality.EXACTLY_ONE,
                    "callback function (as function(xs:string) xs:string*) to provide known JWKs for the given issuer"
                ),
                new FunctionParameterSequenceType(
                    "audience", Type.STRING, Cardinality.ZERO_OR_ONE,
                    "required audience"
                )
            },
            new FunctionReturnSequenceType(Type.MAP, Cardinality.EXACTLY_ONE, "a map of claims from the JWT")
        ),
        GetVerifiedClaimsFunction.class
    );

    private AnalyzeContextInfo analyzeContext;

    public GetVerifiedClaimsFunction(XQueryContext ctx) {
        super(ctx, DEFINITION.getSignature());
    }
    public GetVerifiedClaimsFunction(XQueryContext ctx, FunctionSignature sig) {
        super(ctx, sig);
    }

    @Override
    public void analyze(AnalyzeContextInfo contextInfo) throws XPathException {
        super.analyze(contextInfo);
        // note: need this to analyze the callback
        analyzeContext = new AnalyzeContextInfo(contextInfo);
    }

    @Override
    public Sequence eval(Sequence[] args, Sequence contextSequence) throws XPathException {
        // unpack arguments (mostly already type-checked by super)
        String jwt = args[0].getStringValue();
        FunctionReference callback = (FunctionReference) args[1].itemAt(0);
        String audience = null;
        if (!args[2].isEmpty()) {
            audience = args[2].getStringValue();
        }

        JwtContext unverified;
        try {

            // parse the JWT, but don't verify yet
            unverified = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build()
                .process(jwt);

            // find the issuer, if there is one
            String issuer = unverified.getJwtClaims().getIssuer();

            // get keys (as sequence of JSON strings) from the callback
            Sequence[] callbackArgs;
            if (issuer != null) {
                callbackArgs = new Sequence[] { new StringValue(issuer) };
            } else {
                callbackArgs = new Sequence[] { Sequence.EMPTY_SEQUENCE };
            }
            callback.analyze(analyzeContext);
            Sequence keys = callback.evalFunction(
                null, null, // no context sequence or context item
                callbackArgs
            );

            // and parse them
            // note: Sequence is dumb and doesn't have a proper iterator...
            Vector<JsonWebKey> keySet = new Vector<JsonWebKey>();
            for (int i=0; i<keys.getItemCount(); i++) {
                keySet.add(
                    JsonWebKey.Factory.newJwk(
                        keys.itemAt(i).getStringValue()
                    )
                );
            }
            // and wrap them in resolvers
            JwksVerificationKeyResolver vresolver = new JwksVerificationKeyResolver(keySet);
            JwksDecryptionKeyResolver dresolver = new JwksDecryptionKeyResolver(keySet);


            // verify the JWT
            JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(60)
                .setVerificationKeyResolver(vresolver)
                .setDecryptionKeyResolver(dresolver);
            if (audience != null) {
                builder.setExpectedAudience(audience);
            }
            builder.build().processContext(unverified);

        }
        catch (InvalidJwtException|MalformedClaimException|JoseException e) {
            throw new XPathException(
                this,
                JwtErrorCode.errorFor(e),
                e.getMessage(),
                args[0],
                e
            );
        }

        // if we got this far, the JWT is verified and good to go!
        JwtClaims claims = unverified.getJwtClaims();

        if (context == null) throw new XPathException("null context");

        // return the claims as a map()
        return ClaimsTranslator.translate(claims, this.context);
    }

}
