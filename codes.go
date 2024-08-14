package hdm

var codes = map[int16]string{
	200: "200 - Operation completed successfully",
	500: "500 - Cash register internal error. General type unclassified error",
	400: "400 - Request error. Returned when the request is not decoded",
	101: "101 - Password encryption error",
	102: "102 - Session key encryption error",
	103: "103 - Header format error",
	104: "104 - Query sequence number error",
	105: "105 - JSON formatting error",
	141: "141 - Last receipt record is missing",
	142: "142 - Last check belongs to another user",
}
