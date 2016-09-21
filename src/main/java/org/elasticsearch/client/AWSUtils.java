package org.elasticsearch.client;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.Header;

import com.onekloud.auth.AWSSigneHelper;

public class AWSUtils {
	public static String getSignedHeaders(Header... headers) {
		StringBuilder signedHeaders = new StringBuilder();
		for (Header header : headers) {
			if (signedHeaders.length() > 0)
				signedHeaders.append(";");
			signedHeaders.append(header.getName());
		}
		return signedHeaders.toString().toLowerCase();
	}

	/**
	 * Create the singing authorization code this.datetime = AWSUtils.AWSDateTime.get().format(now); // yyyyMMdd'T'HHmmss'Z'
	 * 
	 * @see http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
	 */
	public static String createSinging(Date date, String region, String service, String canonicalRequest) {

		String datetime = AWSSigneHelper.AWSDateTime.get().format(date); // yyyyMMdd'T'HHmmss'Z'
		String dateStr = AWSSigneHelper.AWSDate.get().format(date); // yyyyMMdd'T'HHmmss'Z'

		StringBuilder sb = new StringBuilder();
		sb.append("AWS4-HMAC-SHA256\n");
		sb.append(datetime).append("\n");
		sb.append(dateStr).append("/").append(region).append("/").append(service).append("/aws4_request\n");
		sb.append(AWSSigneHelper.digestSha256(canonicalRequest));
		return sb.toString();
	}

	/**
	 * Create the canonical request from aws
	 * 
	 * WARNING headers must be ordered
	 * 
	 * http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	 */
	public static String createCanonicalRequest(String method, String requestUri, String query, String payload, Header... headers) {
		if (query == null)
			query = "";
		StringBuilder sb = new StringBuilder();
		sb.append(method).append("\n");
		String encodedUri = requestUri;
		try {
			encodedUri = urlEncode(encodedUri, true);
		} catch (Exception e) {
		}
		sb.append(encodedUri).append("\n");
		sb.append(query).append("\n");
		// CanonicalHeaders
		for (Header header : headers) {
			sb.append(header.getName().toLowerCase()).append(":").append(header.getValue()).append("\n");
		}
		sb.append("\n");
		// SignedHeaders
		sb.append(getSignedHeaders(headers));
		sb.append("\n");
		// HexEncode(Hash(RequestPayload))
		sb.append(AWSSigneHelper.digestSha256(payload)); // HashedPayload
		return sb.toString();
	}

	private static final String DEFAULT_ENCODING = "UTF-8";

	/**
	 * Regex which matches any of the sequences that we need to fix up after URLEncoder.encode().
	 */
	private static final Pattern ENCODED_CHARACTERS_PATTERN;

	static {
		StringBuilder pattern = new StringBuilder();

		pattern.append(Pattern.quote("+")).append("|").append(Pattern.quote("*")).append("|").append(Pattern.quote("%7E")).append("|")
				.append(Pattern.quote("%2F"));

		ENCODED_CHARACTERS_PATTERN = Pattern.compile(pattern.toString());
	}

	/**
	 * Encode a string for use in the path of a URL; uses URLEncoder.encode, (which encodes a string for use in the query portion of a URL), then applies some
	 * postfilters to fix things up per the RFC. Can optionally handle strings which are meant to encode a path (ie include '/'es which should NOT be escaped).
	 *
	 * @param value
	 *            the value to encode
	 * @param path
	 *            true if the value is intended to represent a path
	 * @return the encoded value
	 */
	public static String urlEncode(final String value, final boolean path) {
		if (value == null) {
			return "";
		}
		try {
			String encoded = URLEncoder.encode(value, DEFAULT_ENCODING);
			Matcher matcher = ENCODED_CHARACTERS_PATTERN.matcher(encoded);
			StringBuffer buffer = new StringBuffer(encoded.length());
			while (matcher.find()) {
				String replacement = matcher.group(0);

				if ("+".equals(replacement)) {
					replacement = "%20";
				} else if ("*".equals(replacement)) {
					replacement = "%2A";
				} else if ("%7E".equals(replacement)) {
					replacement = "~";
				} else if (path && "%2F".equals(replacement)) {
					replacement = "/";
				}
				matcher.appendReplacement(buffer, replacement);
			}
			matcher.appendTail(buffer);
			String encodedPath = buffer.toString();
			if (Boolean.TRUE) { // escapeDoubleSlash
				encodedPath = encodedPath.replace("//", "/%2F");
			}
			return encodedPath;

		} catch (UnsupportedEncodingException ex) {
			throw new RuntimeException(ex);
		}
	}

}
