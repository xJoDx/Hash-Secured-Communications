package com.example.requestsender;

import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/* CLASS: Host
 * ATTRIBUTES:
 *      - String address: The complete URL of the host. In a real life situation, the address would
 *        only be the IP address or domain name, the use of the full URL is limited to the specific
 *        experimental context of this implementation
 *      - String time: Date and time of the first request to be sent to this host, in a string format
 *      - Integer nbPacket: Number of requests that were exchanged between the client application and
 *        the server.
 *
 * AIM: Each instance represents a different host with which the application is able to communicate
 *      with and assess the legitimacy by comparing the received security hash with another one that
 *      is generated each time locally.
 *
 * PROCESS:
 *      The main goal of this class is to generate a "Host" object that will be used to represent
 *      a distant server with which the client application is communicating.
 *      The requests are counted as follows in the "nbPacket" value:
 *      nbPacket is always equal to the number of requests that were declared legitimate PREVIOUSLY:
 *          1. The first client request is calculated using nbPacket = 0
 *          2. The server calculates the hash with nbPacket = 0 and the time put in the header
 *          3. The server replies with a new security hash generated using nbPacket = 1 (one request was acknowledged as legitimate)
 *          4. The client application calculates a security hash using nbPacket = 1 (only one request was acknowledged as legitimate)
 *          5. The client application calculates a security hash using nbPacket = 2 (two requests were declared legitimate)
 *          6. The server receives a request and calculates a security hash using nbPacket = 2
 *          ...
 *
 */
public class Host {
    private String address;
    private String time;
    private Integer nbPacket;

    /* CONSTRUCTOR 1
     * This constructor only takes an address (in string format) and is used when the application
     * sends a request to a new host: the class instance will be initialized with the current time
     * as "time" and 0 as "nbPacket".
     */
    public Host(String remote_addr){
        this.address = remote_addr;
        this.time = java.text.DateFormat.getDateTimeInstance().format(new Date());
        this.nbPacket = 0;
    }

    /* CONSTRUCTOR 2
     * This constructor takes the 3 attributes of a Host class instance as parameters and is used
     * when getting the persistent values stored in the "hosts.txt" file. This allows to create a
     * fully functional Host instance from the information stored in the database.
     */
    public Host(String remote_addr, String time, Integer nbPacket){
        this.address = remote_addr;
        this.time = time;
        this.nbPacket = nbPacket;
    }

    public String getRemoteAddress() { return this.address; } //Address property
    public String getTime() {return this.time;} //Time property
    public Integer getNbPacket() {return this.nbPacket;} //NbPacket property
    public void IncrementNbPacket() {this.nbPacket += 1;} //Used to add 1 after a request is sent or received
    public void setRemoteAddress(String address) {this.address = address;} //Used to modify the address after creation

    /* FUNCTION: generateHash()
     * RETURNS: String
     * PARAMETERS: none
     *
     * AIM: Generate the security hash for a specific request to or from an instance of the Host class
     *
     * PROCESS: Call the function "shaIt" - which returns the SHA-256 hash of any string passed as parameter - to
     * create a unique hash corresponding to this value:
     *         SHA256( SHA256([Time of the first request]) + [string value of the number of requests exchanged] )
     */
    public String generateHash() {
        return(shaIt(shaIt(time) + nbPacket.toString()));
    }

    /* FUNCTION: generateHeaders()
     * RETURNS: Map<String, String>
     * PARAMETERS: none
     *
     * AIM: Generate the HashMap that will be used to create the HTTP HEADERS of each request.
     *
     * PROCESS:
     *      1. Check if more than 2 requests were exchanged between the application and the host,
     *         which could indicate that at least one request has been sent back by the host.
     *      2. If it is not the case, it is useful and necessary to specify at what time the first
     *         request was sent. Thus, the correct value is put in the header "X-Time-Sent"
     *      3. If it is the case, the host is considered as "knowing" the time of the first request
     *         so a generic value (i.e., "[YOU HAVE TO KNOW]") is put in the header to avoid giving
     *         away any information that could help an attacker to guess the correct value of the
     *         next hash
     *      4. Increment the number of sent requests so that the next time a hash is generated (for
     *         example when comparing the server response with a local version of the hash), the
     *         number of request is already correct.
     */
    public Map<String, String> generateHeaders(){
        Map<String, String> params = new HashMap<>();
        if(nbPacket < 2){
            params.put("X-Time-Sent",time);
        }
        else{
            params.put("X-Time-Sent", "[YOU HAVE TO KNOW]");
        }
        params.put("X-CheckSum", generateHash());
        this.IncrementNbPacket();
        return params;
    }

    //region Utilities
    /* FUNCTION: shaIt(String toHash)
     * RETURNS: String
     * PARAMETERS:
     *      - String toHash: string value to be hashed by the function
     *
     * AIM: Generate the SHA-256 value of a UTF-8 encoded string
     *
     * PROCESS:
     *      1. Create a MessageDigest instance that will use the SHA-256 algorithm.
     *      2. Generate a byte array representing the hashed value of the string to hash
     *      3. Use a string builder (stackoverflow, 2019) to obtain a string value in hexadecimal format
     *      4. Return the hashed string
     */
    private String shaIt(String toHash) {
        String strHash = "";
        byte[] bHash;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); //STEP 1
            bHash = sha256.digest(toHash.getBytes(StandardCharsets.UTF_8)); //STEP 2
            //STEP 3
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bHash.length; i++) {
                sb.append(Integer.toString((bHash[i] & 0xff) + 0x100, 16).substring(1));
            }
            strHash = sb.toString();
            //END OF STEP 3
        } catch (java.security.NoSuchAlgorithmException e) {
            Log.e("SHA","Problem with SHA 256");
        }
        return strHash; //STEP 4
    }

    /* FUNCTION: toStringForLog()
     * RETURNS: String
     * PARAMETERS: none
     *
     * AIM: Return the line that should be inserted in the "hosts.txt" for persistence.
     *
     * NB: 2 is added to nbPacket to represent
     */
    public String toStringForLog(){
        Integer tempNb = nbPacket + 2;
        return address + ";" + time + ";" + (tempNb).toString() + "\r";
    }
    //endregion
}
