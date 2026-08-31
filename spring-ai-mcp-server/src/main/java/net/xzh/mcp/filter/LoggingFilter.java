package net.xzh.mcp.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;

public class LoggingFilter implements Filter {

	private static final Logger log = LoggerFactory.getLogger(LoggingFilter.class);

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		log.debug("Filter - {} {}", req.getMethod(), req.getRequestURI());
		Enumeration<String> headerNames = req.getHeaderNames();
		Collections.list(headerNames)
				.forEach(headerName -> log.debug("Header: {} = {}", headerName, req.getHeader(headerName)));
		chain.doFilter(request, response);
	}
}