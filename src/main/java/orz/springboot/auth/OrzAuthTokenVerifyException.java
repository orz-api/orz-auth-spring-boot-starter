package orz.springboot.auth;

import lombok.Getter;
import orz.springboot.base.description.OrzDescription;

import static orz.springboot.base.description.OrzDescriptionUtils.descEmpty;
import static orz.springboot.base.description.OrzDescriptionUtils.descValues;

@Getter
public class OrzAuthTokenVerifyException extends Exception {
    private final OrzAuthTokenVerifyError error;
    private final OrzDescription description;

    public OrzAuthTokenVerifyException(OrzAuthTokenVerifyError error, OrzDescription description) {
        this(error, description, null);
    }

    public OrzAuthTokenVerifyException(OrzAuthTokenVerifyError error, Throwable cause) {
        this(error, descEmpty(), cause);
    }

    public OrzAuthTokenVerifyException(OrzAuthTokenVerifyError error, OrzDescription description, Throwable cause) {
        super(descValues("error", error).merge(description).toString(), cause);
        this.error = error;
        this.description = description;
    }
}
