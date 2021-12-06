import { parse } from "cookie"

/* Username and password for auth */
const BASIC_USERS = ['admin','mellon']
const BASIC_PASS = 'admin'
const USER_ID_HEADER = 'X-Secure-User-Id'

/* Redirect location details */
const NEW_LOCN_HOST = "developers.cloudflare.com";
const PROTOCOL = "https://"
const ABOUT_PAGE = "/workers/about"

/* Regexp to represent curl user agent */
const CURL_UA_REGX = /curl\/[0-9\.]+$/

/* Name of the cookie to control redirect behavior */
const REDIR_COOKIE_NAME = "cf-noredir"

addEventListener('fetch', event => {
    event.respondWith(
	handleRequest(event.request).catch(err => {
	    const message = err.reason || err.stack || 'Unknown Error'
	    return new Response(message, {
		status: err.status || 500,
		statusText: err.statusText || null,
		headers: {
		    'Content-Type': 'text/plain;charset=UTF-8',
		    // Disables caching by default.
		    'Cache-Control': 'no-store',
		    // Returns the "Content-Length" header for HTTP HEAD requests.
		    'Content-Length': message.length,
		}
	    })
	})
    )
})

/**
 * Check basic auth header for valid users
 * and allow access only if user is in allowed list
 * adapted from : https://developers.cloudflare.com/workers/examples/basic-auth
 * @param {Request} request
 */
async function handleRequest(request) {
    const { protocol, pathname } = new URL(request.url)
    switch(pathname) {
    case '/secure': {
	// In the case of a "Basic" authentication, the exchange 
	// MUST happen over an HTTPS (TLS) connection to be secure.
	if ('https:' !== protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
	    throw new BadRequestException('Please use a HTTPS connection.')
	} 
	
	if (request.headers.has('Authorization')) {
            // Throws exception when authorization fails.
            const { user, pass } = basicAuthentication(request)
            verifyCredentials(user, pass)

            // Only returns this response when no exception is thrown.
	    const modifiedRequest = new Request(request.url, {
		body: request.body,
		headers: request.headers,
		method: request.method,
		redirect: request.redirect
	    })
	    modifiedRequest.headers.set(USER_ID_HEADER,user);
            return fetch(modifiedRequest);
	}
	return new Response("Blocked - No access to this page", { status: 403 })  
    }

    case '/headers': {
	let reqUA = request.headers.get('user-agent');
	//console.log('Request user agent: ' + reqUA);
	let disableRedir = false;
	const cookie = parse(request.headers.get("Cookie") || "");
	//console.log(cookie);
	if (cookie[REDIR_COOKIE_NAME] == "true") {
	    // redirection disabled. fetch original request
	    //console.log('Redirect cookie set to true. Disabling redirect');
	    disableRedir = true;
	}else {
	    //console.log('Redirect cookie NOT set');
	}

	if (reqUA.match(CURL_UA_REGX) && !disableRedir) {
	    /* User agent matches curl UA Regexp */
	    /* Redirect to new location */
	    //console.log('User agent matches Curl, redirecting...');
	    let newLocation = PROTOCOL + NEW_LOCN_HOST + ABOUT_PAGE;
	    return Response.redirect(newLocation, 302);
	}

	/* Not curl. Let the request pass through to the original url */
	return fetch(request);
    }
    }

    /* No special logic. Let the request pass through to the original url */
    return fetch(request);
}

/**
 * Parse HTTP Basic Authorization value.
 * @param {Request} request
 * @throws {BadRequestException}
 * @returns {{ user: string, pass: string }}
 */
function basicAuthentication(request) {
    const Authorization = request.headers.get('Authorization')

    const [scheme, encoded] = Authorization.split(' ')

    // The Authorization header must start with "Basic", followed by a space.
    if (!encoded || scheme !== 'Basic') {
	throw new BadRequestException('Malformed authorization header.')
    }

    // Decodes the base64 value and performs unicode normalization.
    // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
    // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
    const decoded = atob(encoded).normalize()
    
    // The username & password are split by the first colon.
    //=> example: "username:password"
    const index = decoded.indexOf(':')

    // The user & password are split by the first colon and MUST NOT contain control characters.
    // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
    if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
	throw new BadRequestException('Invalid authorization value.')
    }
    
    return { 
	user: decoded.substring(0, index),
	pass: decoded.substring(index + 1),
    }
}

function BadRequestException(reason) {
    this.status = 400
    this.statusText = 'Bad Request'
    this.reason = reason
}

function UnauthorizedException(reason) {
    this.status = 401
    this.statusText = 'Unauthorized'
    this.reason = reason
}

/**
 * Throws exception on verification failure.
 * @param {string} user
 * @param {string} pass
 * @throws {UnauthorizedException}
 */
function verifyCredentials(user, pass) {
    if (BASIC_USERS.find(element => element == user) == undefined) {
	throw new UnauthorizedException('Invalid username.')
    }

    /*
    if (BASIC_PASS !== pass) {
	throw new UnauthorizedException('Invalid password.')
    }
    */
}


