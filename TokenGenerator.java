package com.sc.controller.web;

import java.io.UnsupportedEncodingException;
import java.sql.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class TokenGenerator {

	private final static long MINUTE_IN_MILLIS = 180000000;
	private final static String SIGNINGKEY = "SHELDONCHANG";
	private final static String ACCOUNT = "account";
	private final static String PASSWORD = "password";

	public TokenGenerator() {
		super();
	}

	public static String getToken(String account, String password) {
		Date date = new Date(MINUTE_IN_MILLIS + System.currentTimeMillis());
		String token = "no-access-token";
		try {
			token = Jwts.builder().setExpiration(date).claim(ACCOUNT, account).claim(PASSWORD, password)
					.signWith(SignatureAlgorithm.HS512, SIGNINGKEY.getBytes("UTF-8")).compact();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return token;
	}

	public static boolean validateToken(String token) {
		if (null == deToken(token)) {
			return false;
		}
		Long expTime = deToken(token).getExpiration().getTime();
		return ((expTime - System.currentTimeMillis()) >= 0);
	}

	public static String getAccount(String token) {
		return (String) deToken(token).get(ACCOUNT);
	}

	public static String getPassword(String token) {
		return (String) deToken(token).get(PASSWORD);
	}

	private static Claims deToken(String token) {
		Claims claims = null;
		try {
			claims = Jwts.parser().setSigningKey(SIGNINGKEY.getBytes("UTF-8")).parseClaimsJws(token).getBody();
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException
				| IllegalArgumentException | UnsupportedEncodingException e) {
			System.out.println("Decoding failed.");
			e.printStackTrace();
		}
		return claims;
	}
}
