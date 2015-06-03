package ca.terpstra.max.exist_jwt;

import org.exist.xquery.*;
import org.exist.xquery.value.*;
import org.exist.xquery.functions.map.*;
import org.jose4j.jwt.consumer.*;

import java.util.Map;
import java.util.List;

/**
 * JWT management module
 */
public class JwtModule extends AbstractInternalModule {
    public final static String NAMESPACE_URI = "http://max.terpstra.ca/ns/exist-jwt";
    public final static String PREFIX = "jwt";
    public final static String DESCRIPTION = "JWT parser/verifier";

    private final static FunctionDef[] functions = {
        GetVerifiedClaimsFunction.DEFINITION
    };

    public JwtModule() {
        super(functions, null);
    }
    public JwtModule(Map<String, List<?>> parameters) {
        super(functions, parameters);
    }

    @Override
    public String getNamespaceURI() {
        return NAMESPACE_URI;
    }
    @Override
    public String getDefaultPrefix() {
        return PREFIX;
    }
    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
    @Override
    public String getReleaseVersion() {
        return ""; // FIXME?
    }
    
}
