CREATE OR REPLACE FUNCTION account_signup(_account_type TEXT, _username TEXT,
                               _password_hash TEXT, _first_name TEXT,
                               _last_name TEXT, _company_name TEXT, _email TEXT,
                               _phone_number TEXT, _bio TEXT,
                               _latitude NUMERIC, _longitude NUMERIC,
                               _facebook_user_id TEXT DEFAULT NULL)
RETURNS JSONB
LANGUAGE PLPGSQL
AS
$$
DECLARE
  _response JSONB;
  _account_id INTEGER;
BEGIN
  -- TODO check signups and reserved_usernames table
  IF NOT account_username_available(_username) THEN
    SELECT json_build_object('success', FALSE,
                             'status', 'username_exists',
                             'message', 'An account with that username already exists.')::JSONB
           INTO _response;
    RETURN _response;
  END IF;
  IF EXISTS (SELECT 1 FROM accounts WHERE email = _email) THEN
    SELECT json_build_object('success', FALSE,
                             'status', 'email_exists',
                             'message', 'An account with that email already exists.')::JSONB
           INTO _response;
    RETURN _response;
  END IF;
  IF EXISTS (SELECT 1 FROM accounts WHERE facebook_user_id = _facebook_user_id
                                    AND facebook_user_id IS NOT NULL) THEN
    SELECT json_build_object('success', FALSE,
                             'status', 'facebook_user_exists',
                             'message', 'An account for that Facebook account already exists.')::JSONB
           INTO _response;
    RETURN _response;
  END IF;
  INSERT INTO accounts (account_type, username, password, first_name,
                        last_name, company_name, email, phone_number, bio,
                        latitude, longitude, facebook_user_id, custom_url)
  VALUES (_account_type, LOWER(_username), _password_hash,
          _first_name, _last_name, _company_name, LOWER(_email), _phone_number,
          _bio, _latitude, _longitude, _facebook_user_id, LOWER(_username))
  RETURNING account_id INTO _account_id;

  IF _facebook_user_id IS NOT NULL THEN
    INSERT INTO account_verifications (account_id, verification_id)
    SELECT _account_id, verification_id
    FROM verifications
    WHERE verification_name = 'facebook'
    AND verification_id NOT IN (SELECT verification_id
                                FROM account_verifications
                                WHERE account_id = _account_id);
  END IF;
  SELECT json_build_object('success', TRUE,
                           'status', 'success',
                           'message', 'Account created successfully.',
                           'account_id', _account_id)::JSONB
         INTO _response;
  RETURN _response;
END;
$$;
