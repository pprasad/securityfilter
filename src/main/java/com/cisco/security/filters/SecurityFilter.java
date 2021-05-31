package com.cisco.security.filters;

import static com.cisco.security.util.SecurityContants.addExcludeHeaderValues;
import static com.cisco.security.util.SecurityContants.addExcludeQueryParams;
import static com.cisco.security.util.SecurityContants.getPath;
import static com.cisco.security.util.SecurityContants.getSystemValues;
import static com.cisco.security.util.SecurityContants.isValidCorsUrls;
import static com.cisco.security.util.SecurityContants.isValidRefererHeader;
import static com.cisco.security.util.SecurityContants.isValidURL;
import static com.cisco.security.util.SecurityContants.isVulnerabilityCheckPoint;
import static com.cisco.security.util.SecurityContants.setAllowedHeadersRegex;
import static com.cisco.security.util.SecurityContants.setSecureCookie;
import static com.cisco.security.util.SecurityContants.prepareErrorMessage;
import static com.cisco.security.util.SecurityContants.addExcludeHeaders;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.json.XML;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/*
 * @Auth : umprasad
 * @Desc : Vulnerability filter it will does't allowed SQL,CSS & javascript injections
 */
public class SecurityFilter implements Filter {
	
	private final static Logger LOGGER=LoggerFactory.getLogger(SecurityFilter.class);
	
	private final String EMAN_URL="EMAN_URL";
	
	private final String SESSION_ID="JSESSIONID";
	
	private final String OBSSO_COOKIE="ObSSOCookie";
	
    private final String GEAR_COOKIE="GEAR";
    
    private final String SERVERID_COOKIE="SERVERID";
    
    private final String CISCO_DOMAIN="http://localhost";
	
	private final String IS_SECURITY_RUN="IS_SECURITY_RUN";
	
	private final String IS_SECURITY_RUN_NO="N";
	
	protected final String INVALID_REQUEST= "InValid Request";
	
	private final String ALLOW_CONTEXT_PATH="ALLOW_CONTEXT_PATH";
	
	protected final String ALLOW_HOSTS="ALLOW_HOSTS";
	
	protected final String EDOS_LOGIN_COOKIE="edosLogin";
	
    protected final String ACCESS_DENIDED= "Access to this feature is restricted outside of the Cisco";
    
    private final String APP_COOKIES="APP_COOKIES";
    
    private final String EDOS_AMCV_COOKIE="AMCV_B8D07FF4520E94C10A490D4C%40AdobeOrg";
    
    private final String METHOD_ALLOWED="METHOD_ALLOWED";
    
    private static final String EXECULDE_PATHS="EXECLUDE_PATHS";
    
    private static final String ALLOWED_REFERER="ALLOW_REFERER_HEADERS";
    
    private static final String ALLOWED_ORIGIN_HEADERS="ALLOW_ORIGIN_HEADERS";
    
    private static final String ALLOWED_HEADERS="ALLOW_HEADERS";
    
    private static final String EXCLUDE_HEADER_VALUES="EXCLUDE_HEADER_VALUES";
    
    private static final String EXCLUDE_HEADERS="EXCLUDE_HEADERS";
    
    private static final String EXCLUDE_QUERY_PARAMS="EXCLUDE_QUERY_PARAMS";
    
    private String allowedReferers=null;
    
	private String emanURL=null;
	
	private String allowContextPath=null;
	
	private List<String> appCookies;
	
	private List<String> ALLOW_METHODS;
	
	private List<String> execludePaths;
	
	private String allowedCorsHeaders=null;
	
	public void init(FilterConfig config) throws ServletException {
		emanURL=getSystemValues(config,EMAN_URL);
		String methodAllows=getSystemValues(config,"METHOD_ALLOWED");
		execludePaths=new ArrayList<String>();
		if(methodAllows==null){methodAllows=getSystemValues(config,METHOD_ALLOWED);}
	
		String appCookie=getSystemValues(config,APP_COOKIES);
		if(appCookie!=null) {
			appCookies=new ArrayList<String>();
			for(String s:appCookie.split(",")){
				LOGGER.info("App Cookie{}"+s);
			    appCookies.add(s);
			}
		}else{
			appCookies=new ArrayList<String>();
		}
		/*Http Methods*/
		if(methodAllows!=null){
	    	ALLOW_METHODS=new ArrayList<String>();
	    	for(String s:methodAllows.split(",")){
	    		ALLOW_METHODS.add(s);
	    	}
	    }
		String execludePath=getSystemValues(config,EXECULDE_PATHS);
		if(execludePath!=null) {
			for(String s:execludePath.split(",")) {
				execludePaths.add(s);
			}
		}
		allowContextPath=getSystemValues(config,ALLOW_CONTEXT_PATH);
		//Allowed Refereres
		allowedReferers=getSystemValues(config,ALLOWED_REFERER);
		//Allowed White List Headers
		String allowedHeaders=getSystemValues(config,ALLOWED_HEADERS);
		LOGGER.info("AllowedHeaders:{}",allowedHeaders);
		if(allowedHeaders!=null){
			allowedHeaders=allowedHeaders.replaceAll(",","|");
			StringBuilder headersRegex=new StringBuilder();
			headersRegex.append("\\b").append("(").append(allowedHeaders).append(")\\b");
			setAllowedHeadersRegex(headersRegex.toString());
	    }
		//Allow Cross origin Url's
		this.allowedCorsHeaders=getSystemValues(config,ALLOWED_ORIGIN_HEADERS);
		//ExcludeHeaders & validate after decoding
		addExcludeHeaderValues(config,EXCLUDE_HEADER_VALUES);
		//Exclude Query params from security check
		addExcludeQueryParams(config,EXCLUDE_QUERY_PARAMS);
		//Exclude Header Values
		addExcludeHeaders(config,EXCLUDE_HEADERS);
	}
	
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,FilterChain filterChain)
			throws IOException, ServletException {
		 String errorMsg=null;
		 HttpServletRequest request=(HttpServletRequest)servletRequest;
		 HttpServletResponse response=(HttpServletResponse)servletResponse;
		 addCustomerHeaders(response);
	     XSSRequestWrapper requestWrapper=new XSSRequestWrapper(request);
	     String requestBody=requestWrapper.getBody();
	     if(requestBody!=null && requestWrapper.isXmlRequest()) {
	    	 JSONObject xmlToJson=XML.toJSONObject(requestBody);
			 requestBody=xmlToJson.toString();
	     }
	     String queryString=requestWrapper.getQueryString();
	     String url=request.getRequestURI();
	     boolean isHeaderAllow=requestWrapper.isHeaderAllowed();
	     setSSLCookies(requestWrapper,response);
	     String method=requestWrapper.getMethod();
	     boolean isMethodAllow=hasMethodAllowed(method);
	     LOGGER.info("isMethodAllow::{}"+isMethodAllow);
	     boolean isValidRequestBody=isVulnerability(requestBody,url);
	     boolean isValidQueryString=isVulnerability(queryString,url);
	     String originUrl=request.getHeader("Origin");
	     LOGGER.info("Origin URL:{}",originUrl);
	     LOGGER.info("isHeaderAllow::{}",isHeaderAllow);
 	     LOGGER.info("isValidRequestBody::{}",isValidRequestBody);
 	     LOGGER.info("isValidQueryString::{}",isValidQueryString);
 	     errorMsg=prepareErrorMessage(isHeaderAllow,isMethodAllow,isValidRequestBody,isValidQueryString);
	     if(isCrossSiteRequest(requestWrapper) && isMethodAllow && isValidCorsUrls(this.allowedCorsHeaders,originUrl)){
	    	 if(isHeaderAllow && isValidQueryString && isValidRequestBody){
	    		 filterChain.doFilter(requestWrapper,response);
	    	 }
	     }else{
	    	 errorMsg=ACCESS_DENIDED;
	     }
		 if(errorMsg!=null) {
			LOGGER.info("isMethodAllow{}"+isMethodAllow);
			response.setStatus(isMethodAllow?500:400);
			response.sendError(isMethodAllow?HttpServletResponse.SC_BAD_REQUEST:HttpServletResponse.SC_METHOD_NOT_ALLOWED);
			response.setContentType("text/html");
			request.setAttribute("error_msg",errorMsg);
			response.getOutputStream().write(errorMsg.getBytes());
			response.getOutputStream().flush();
			response.getOutputStream().close();
		}
	}
	private boolean hasMethodAllowed(String method){
		  LOGGER.info("****************Method Checking***********************");
		  LOGGER.info("Method:{}",method);
		  Boolean flag=Boolean.FALSE;  
		  if(ALLOW_METHODS!=null && ALLOW_METHODS.contains(method.toUpperCase())){
			  flag=Boolean.TRUE;
		  }else{
			  flag=Boolean.FALSE;
		  }
		  LOGGER.info("After method checking flag{}"+flag); 
		  return flag; 
	}
	private void setSSLCookies(HttpServletRequest request,HttpServletResponse response){
		LOGGER.info("<<<<<<<<<<<Enter into setSSLCookies>>>>>>>>>>>>>>>");
		LOGGER.info("Application Related Cookies:{}",(appCookies!=null && !appCookies.isEmpty()?appCookies.toArray():null));
		Cookie []cookies=request.getCookies();
    	if(cookies!=null){
			  for(Cookie cookie:cookies){ 
				  LOGGER.info("cookie.getName:{}-->comments:{}--->Secure:{}",cookie.getName(),cookie.getComment(),cookie.getSecure());
				  if(cookie.getName().equalsIgnoreCase(OBSSO_COOKIE)||cookie.getName().equalsIgnoreCase(SESSION_ID)){                    
					  setSecureCookie(response,cookie);
				  }else if(cookie.getName().equalsIgnoreCase(GEAR_COOKIE)||cookie.getName().equalsIgnoreCase(SERVERID_COOKIE)){
					  setSecureCookie(response,cookie);
				  }else if(cookie.getName().equalsIgnoreCase(EDOS_LOGIN_COOKIE) || cookie.getName().equalsIgnoreCase(EDOS_AMCV_COOKIE)) {
					  setSecureCookie(response,cookie);
				  }else if(appCookies!=null && !appCookies.isEmpty() && appCookies.contains(cookie.getName()) && (!cookie.getSecure()||cookie.getComment()==null)){
					  LOGGER.info("<<<<<Application related cookies>>>>>>");
					  setSecureCookie(response,cookie);
				  }
			  }
		}
    	LOGGER.info("<<<<<<<<<<<End setSSLCookies>>>>>>>>>>>>>>>");	
	}
	
	private boolean isCrossSiteRequest(HttpServletRequest request) {
		LOGGER.info("<<<<<<<<<<<Enter isCrossSiteRequest>>>>>>>>>>>>>>>");
		boolean flag=false;
    	String referer=request.getHeader("Referer");
    	String requestURL=request.getRequestURI();
    	String hostUrl=request.getRequestURL().toString();
    	LOGGER.info("Before Referer::{}--->Request URL::{}-->Host With Request URL::{}",referer,requestURL,hostUrl);
    	LOGGER.info("Allowed ContextPath:{}",allowContextPath);
    	if(referer==null){
    	    referer=CISCO_DOMAIN;
    	}
    	LOGGER.info("After Referer::{}"+referer);
    	if(isValidRefererHeader(referer,allowedReferers) && (isValidURL(hostUrl)||(allowContextPath!=null &&
    			hostUrl.contains(allowContextPath)))) {
    		flag=true;
    	}else if(requestURL!=null && requestURL.equals(emanURL)){
    		flag=true;
    	}
        LOGGER.info("<<<<<<<<<<<End isCrossSiteRequest>>>>>>>>>>>>>>>");
        return flag;
	}
	private boolean isVulnerability(String requestData,String url) {
		LOGGER.info("<<<<<<<<<<<Start isVulnerability>>>>>>>>>>>>>>>");
		boolean flag=true;
		LOGGER.info("Request Data{}::"+requestData);
		url=getPath(url);
		LOGGER.info("Execlude Paths:{}",execludePaths.toString());
		if(requestData!=null && isSecurityFilter() && !execludePaths.contains(url)){
			LOGGER.info("****Started Validate on Body (Or) Query Parameters*****");
	    	flag=isVulnerabilityCheckPoint(requestData);
    	}else{
    		flag=true;
    	}
		LOGGER.info("Is Valid Request Data::{}",flag);
		LOGGER.info("<<<<<<<<<<<End isVulnerability>>>>>>>>>>>>>>>");
		return flag;
	}
	private boolean isSecurityFilter() {
		LOGGER.info("<<<<<<<<<<<Start isSecurityFilter>>>>>>>>>>>>>>>");
		String isRun=System.getProperty(IS_SECURITY_RUN);
		LOGGER.info("Before IS_SECURITY_RUN::{}",isRun);
		if(isRun==null) {
			isRun=System.getenv(IS_SECURITY_RUN);
		}
		LOGGER.info("After IS_SECURITY_RUN::{}",isRun);
		LOGGER.info("<<<<<<<<<<<End isSecurityFilter>>>>>>>>>>>>>>>");
		return (isRun!=null && IS_SECURITY_RUN_NO.equals(isRun))?false:true;
	}
	private void addCustomerHeaders(HttpServletResponse response){
		response.addHeader("Cache-Control","no-store");
		response.addHeader("Pragma","no-cache");
		response.addHeader("X-Content-Type-Options","nosniff");
		response.addHeader("X-XSS-Protection","1; mode=block");
	}
	public void destroy() {
		
	}
}