/**
 *
 * Useful to identify possible attack surface for IDOR.
 *
 * @author intrudir
 **/
List<String> idorList = Arrays.asList("account","doc","edit","email","group","id","key","no","number","order","profile","report","user");
StringBuilder builder = new StringBuilder();
StringBuilder idorParamsBuilder = new StringBuilder();

HttpRequest request = requestResponse.request();
if (request.hasParameters()){
	boolean foundIdorParam = false;

    for (ParsedHttpParameter parameter : request.parameters()){
        String parameterName = parameter.name();
        String parameterValue = parameter.value();

        if (idorList.contains(parameterName)) {
            foundIdorParam = true;
            idorParamsBuilder.append(parameterName + ", ");
        }

        Matcher m = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",Pattern.CASE_INSENSITIVE).matcher(parameterValue.toString());
        while (m.find()) {
            builder.append(m.group() + " ");  // Append the found UUID to the string
        }
    }
    StringBuilder notes = new StringBuilder();
    if (idorParamsBuilder.length() > 0) {
        notes.append("\n\nPossible IDOR params identified:\n").append(idorParamsBuilder.toString().replaceAll(", $", "")).append("\n");
    }
    if (builder.length() > 0) {
        notes.append("\n\nPossible UUIDs identified for an IDOR attack: ").append(builder.toString());
    }

    // Update the notes in the request
    if (notes.length() > 0) {
        requestResponse.annotations().setNotes(notes.toString());
    }

    return foundIdorParam || builder.length() > 0;
}

return false;
