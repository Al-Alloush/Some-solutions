public class AmazonCustomFilter extends AbstractAuthenticationProcessingFilter {
	

	protected AmazonCustomFilter() {
		super(new AntPathRequestMatcher("/v2/shiptracks", "POST"));
	}

	@SuppressWarnings("unchecked")
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		String xml = null;
		String username;
		String password;
		String jsonPrettyPrintString=null;
		

        ObjectMapper oMapper = new ObjectMapper();
		Map<String, String> requestMap;
		Map<String, String> amazonTrackingRequestMap;
		Map<String, String> validationMap;
		
		String contentType= request.getHeader("Content-Type");
		if("application/xml".equalsIgnoreCase(contentType)) {
			

			byte[] xmlData = new byte[request.getContentLength()];
			//Start reading XML Request as a Stream of Bytes
	        InputStream sis = request.getInputStream();
	        BufferedInputStream bis = new BufferedInputStream(sis);
	        bis.read(xmlData, 0, xmlData.length);
	        if (request.getCharacterEncoding() != null) {
	            xml = new String(xmlData, request.getCharacterEncoding());
	        } else {
	                xml = new String(xmlData);
	        }
	        // start converting String XML to String Json format
	        JSONObject xmlJSONObj = XML.toJSONObject(xml);
	        jsonPrettyPrintString = xmlJSONObj.toString();
	        System.out.println(jsonPrettyPrintString);
	        
	        requestMap = oMapper.readValue(jsonPrettyPrintString, Map.class);
	        amazonTrackingRequestMap = oMapper.convertValue(requestMap.get("AmazonTrackingRequest"), Map.class);
	        validationMap = oMapper.convertValue(amazonTrackingRequestMap.get("Validation"), Map.class);
	        
		}else {
            requestMap = oMapper.readValue(request.getInputStream(), Map.class);
            validationMap = oMapper.convertValue(requestMap.get("Validation"), Map.class);

		}
		
        username = validationMap.get("UserID");
        password = validationMap.get("Password");

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        return this.getAuthenticationManager().authenticate(authRequest);
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
	        Authentication authResult) throws IOException, ServletException {
	    SecurityContextHolder.getContext().setAuthentication(authResult);

	    chain.doFilter(request, response);
	}
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
	        AuthenticationException failed) throws IOException, ServletException {
	    logger.debug("failed authentication while attempting to access ");

	    //Add more descriptive message
	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
	            "Authentication Failed");
	}
