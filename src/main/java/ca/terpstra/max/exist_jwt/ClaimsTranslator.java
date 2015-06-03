package ca.terpstra.max.exist_jwt;

import org.exist.xquery.*;
import org.exist.xquery.value.*;
import org.exist.xquery.functions.map.*;

import org.jose4j.jwt.JwtClaims;

import java.util.List;
import java.util.Map;

public class ClaimsTranslator {

    private ClaimsTranslator() { }; // don't allow this class to be instantiated

    /**
     * Translate a JwtClaims object into an equivalent XQuery map()
     */
    public static Sequence translate(JwtClaims claims, XQueryContext ctx) throws XPathException {
        return translatePart(claims.getClaimsMap(), ctx);
    }

    private static Sequence translatePart(Map<String, ?> map, XQueryContext ctx) throws XPathException {
        MapType result = new MapType(ctx);
        for (Map.Entry<String, ?> e : map.entrySet()) {
            result.add(
                new StringValue(e.getKey()),
                translatePart(e.getValue(), ctx)
            );
        }
        return result;
    }

    private static <T> Sequence translatePart(List<T> list, XQueryContext ctx) throws XPathException {
        Sequence result = new ValueSequence();
        for (T sub : list) {
            result.addAll(translatePart(sub, ctx));
        }
        return result;
    }

    private static Sequence translatePart(Object obj, XQueryContext ctx) throws XPathException {
        if (obj == null) {
            return Sequence.EMPTY_SEQUENCE;
        } else {
            // above overloaded methods would be used instead for Map or List
            return XPathUtil.javaObjectToXPath(obj, ctx);
        }
    }

}
