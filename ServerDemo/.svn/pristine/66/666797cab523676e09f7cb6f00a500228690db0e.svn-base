package cn.zifangsky.controller;


import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.springframework.web.util.WebUtils;


/**
 * 
 * 此类描述的是：   	BaseController
 * @author: 赵亚舟   
 * @version: 2016年6月8日 下午2:12:29
 */
@Controller
public class BaseController {
	protected  HttpServletRequest request;

	@ModelAttribute
	public void initServlt(HttpServletRequest request,HttpServletResponse response){
		request.setAttribute("_baseUrl", request.getContextPath());
		Locale locale = RequestContextUtils.getLocale(request);
		request.setAttribute("_local", locale.getLanguage());
		request.setAttribute("_url", request.getRequestURI());
//		request.setAttribute("_resources", RedisUtil.hget(RedisKeyEnums.SETTINGS.getValue(), "resourcesPath"));
		request.setAttribute("_resources", request.getContextPath()+"/resources/");
	}
	/**
	 * 
	 * @Title: getToken
	 * @Description: 获得验证令牌
	 * @param request
	 * @return String   
	 * @throws
	 * @date 2015-4-17 下午4:09:15
	 */
	protected String getToken(HttpServletRequest request){
		Object token = WebUtils.getSessionAttribute(request, "token");
		return token != null ?token.toString():null;
	}
	
	/**
	 * @return the request
	 */
	public HttpServletRequest getRequest() {
		return request;
	}
	/**
	 * @param request the request to set
	 */
	@Autowired
	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}
	
	/**
	 * 获取客户端ip
	 * @return
	 */
	public String getRemoteHost(){
		String ip = request.getHeader("x-forwarded-for");
		if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)){
			ip = request.getHeader("Proxy-Client-IP");
		}
		if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)){
			ip = request.getHeader("WL-Proxy-Client-IP");
		}
		if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)){
			ip = request.getRemoteAddr();
		}
		//如果通过了多级反向代理，需截取ip
		if(ip != null && ip.indexOf(",") > -1){
			ip = ip.split(",")[0].trim();
		}
		return ip.equals("0:0:0:0:0:0:0:1")?"127.0.0.1":ip;
	}
	
	
	public static boolean isAjax(HttpServletRequest request){
	    String requestType = request.getHeader("X-Requested-With");

	    return (requestType != null) && (requestType.equals("XMLHttpRequest"));
	  }
	
	
	/**
	 * 
	 * @author: 赵亚舟
	 * @Title: getUser_idFormSession
	 * @Description: 获取session中数据
	 * @param user_id
	 * @return
	 * @return String
	 */
	public String getUser_idFormSession(String user_id){
		return (String)request.getSession().getAttribute(user_id);
	}
	
}
