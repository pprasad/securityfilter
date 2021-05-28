package com.cisco.security.filters;

import static com.cisco.security.util.SecurityContants.decodeHeaderValue;
import static com.cisco.security.util.SecurityContants.isValidHeader;
import static com.cisco.security.util.SecurityContants.isVulnerabilityCheckPoint;
import static com.cisco.security.util.SecurityContants.isExcludeQueryParams;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XSSRequestWrapper extends HttpServletRequestWrapper {

	private final static Logger LOGGER=LoggerFactory.getLogger(XSSRequestWrapper.class);
	
	private static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
	
	private static final String METHOD_POST = "POST";
	
	public static final String UTF8 = "UTF-8";
	public final String body;
	public final String queryString;
	public final boolean isHeaderAllowed;
	public final boolean isXmlRequest;
	
	public XSSRequestWrapper(HttpServletRequest request){
		 super(request);
		 StringBuilder bodyData=new StringBuilder();
		 BufferedReader reader=null;
		 String readLine=null;
		 try {
			  if(!this.isFormPost()){
				  InputStream inputStream=request.getInputStream();
				  if(inputStream!=null) {
					  reader=new BufferedReader(new InputStreamReader(inputStream));
					  while((readLine=reader.readLine())!=null) {
						   bodyData.append(readLine);
					  }
				  }
			  }
		 }catch(Exception ex) {
			 LOGGER.error("Exception",ex);
		 }finally {
			 if(reader!=null) {
				 try {
					reader.close();
				 }catch(Exception ex) {
					 LOGGER.error("Exception",ex);
				 }
			 }
		 }
		 if((bodyData!=null && bodyData.length()!=0) &&
				 (request!=null && request.getContentType()!=null && request.getContentType().contains("application/soap+xml"))){
			  this.isXmlRequest=true;
		 }else{
			 this.isXmlRequest=false;
		 }
	     this.body=bodyData.length()==0?null:bodyData.toString();
	     this.queryString=this.getQueryParameters();
	     LOGGER.info("After Body Post Parameters:{}"+this.queryString);
	     this.isHeaderAllowed=this.getHeaders();
	}
	@Override
	public ServletInputStream getInputStream() throws IOException {
		 String data=(body!=null)?body:"";
		 final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data.getBytes());
	        ServletInputStream servletInputStream = new ServletInputStream() {
	            public int read() throws IOException {
	                return byteArrayInputStream.read();
	            }
	        };
	        return servletInputStream;
	}
	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream()));
	}
	private String getQueryParameters() {
		LOGGER.info("****************Start getQueryParameters****************");
		List<String> query=new ArrayList<String>();
		Set<Map.Entry<String,Object>> entrySet=this.getParameterMap().entrySet();
		for(Map.Entry<String,Object> param:entrySet) {
			if(!isExcludeQueryParams(param.getKey())){
				query.add(param.getKey()+"="+this.getParameter(param.getKey()));
			 }
		}
		LOGGER.info("****************END getQueryParameters****************");
		return query.isEmpty()?null:String.join("&",query);
	}
	private boolean getHeaders(){
		boolean flag=true;
		LOGGER.info("List Of Headers:{}",Collections.list(this.getHeaderNames()).toString());
		Enumeration<String> headers=this.getHeaderNames();
		while(headers.hasMoreElements()){
			String key=headers.nextElement();
			if(!"cookie".equalsIgnoreCase(key) && !"accept".equalsIgnoreCase(key)){
				String header=key+"="+decodeHeaderValue(key,this.getHeader(key));
				flag=isValidHeader(key)?isVulnerability(header):false;
				if(!flag){
					break;
				}
			}
		}
		return flag;
	}
	public String getBody() {
		return this.body;
	}
	public String getQueryString() {
		return queryString;
	}
	public boolean isHeaderAllowed() {
		return isHeaderAllowed;
	}
	public boolean isXmlRequest() {
		return isXmlRequest;
	}
	private boolean isVulnerability(String requestData) {
		LOGGER.info("<<<<<<<<<<<Start isVulnerability On Headers>>>>>>>>>>>>>>>");
		LOGGER.info("Header Request Data:{}",requestData);
		boolean flag=true;
		if(requestData!=null){
			LOGGER.info("****Started Validate on Header Data*******");
		    flag=isVulnerabilityCheckPoint(requestData);
    	}else{
    		flag=true;
    	}
		LOGGER.info("Is Valid Header Data::{}",flag);
		LOGGER.info("<<<<<<<<<<<End isVulnerability On Headers>>>>>>>>>>>>>>>");
		return flag;
	}
	public boolean isFormPost() {
		String contentType = getContentType();
		return (contentType != null && contentType.contains(FORM_CONTENT_TYPE) && METHOD_POST.equalsIgnoreCase(getMethod()));
	}
}