<?php

namespace Tsugi\Util;

use \Tsugi\Util\U;

/**
 * This general purpose library for HTTP communications.
 *
 * This class attempts to solve the problem that lots of
 * PHP environments have different approaches to doing
 * GET and POST requests.  Some use CURL and others use
 * context streams.   This code tries one way or another
 * to figure out the best way to handle these and make
 * these calls work using whatever library code that
 * is available.
 *
 * The best way for things work is for CURL to be avaialable.
 * If CURL is available, it is used for everything and
 * forks well.
 *
 * @TODO We need to make this non-static and configure it
 * so it prefers or exclusively uses a particular transport.
 *
 */
class Net {

    public static $VERIFY_PEER = false;

    public static function getLastGETURL() {
        global $LastGETURL;
        return $LastGETURL;
    }
    public static function getLastGETImpl() {
        global $LastGETImpl;
        return $LastGETImpl;
    }
    public static function getLastHeadersSent() {
        global $LastHeadersSent;
        return $LastHeadersSent;
    }
    public static function getLastHttpResponse() {
        global $last_http_response;
        return $last_http_response;
    }
    public static function getLastCurlError() {
        global $LastCurlError;
        return $LastCurlError;
    }
    public static function getLastHeadersReceived() {
        global $LastHeadersReceived;
        return $LastHeadersReceived;
    }
    public static function getLastBODYURL() {
        global $LastBODYURL;
        return $LastBODYURL;
    }
    public static function getLastBODYMethod() {
        global $LastBODYMethod;
        return $LastBODYMethod;
    }
    public static function getLastBODYImpl() {
        global $LastBODYImpl;
        return $LastBODYImpl;
    }
    public static function getLastBODYContent() {
        global $LastBODYContent;
        return $LastBODYContent;
    }

    public static function getLastBODYDebug() {
        global $LastBODYContent;
        global $LastBODYImpl;
        global $LastBODYMethod;
        global $LastBODYURL;
        global $LastHeadersReceived;
        global $LastHeadersSent;
        global $last_http_response;
        global $LastCurlError;

        // Caller knows the body_sent
        $retval = array();
        $retval['code'] = $last_http_response;
        $retval['body_impl'] = $LastBODYImpl;
        $retval['headers_sent'] = $LastHeadersSent;
        $retval['headers_received'] = $LastHeadersReceived;
        return $retval;
    }


    /**
     * Extract a set of header lines into an array
     *
     * Takes a newline separated header sting and returns a key/value array
     */
    public static function parseHeaders($headerstr=false) {
        if ( $headerstr === false ) $headerstr = self::getLastHeadersReceived();
        $lines = explode("\n",$headerstr);
        $headermap = array();

        foreach ($lines as $line) {
            $pos = strpos($line, ':');
            if ( $pos < 1 ) continue;
            $key = substr($line,0,$pos);
            $value = trim(substr($line, $pos+1));
            if ( empty($key) || empty($value) ) continue;
            $headermap[$key] = $value;
        }
        return $headermap;
    }

    public static function doGet($url, $header = false) {
        global $LastGETURL;
        global $LastGETImpl;
        global $LastHeadersSent;
        global $last_http_response;
        global $LastCurlError;
        global $LastHeadersReceived;

        $LastGETURL = $url;
        $LastGETImpl = false;
        $LastHeadersSent = false;
        $last_http_response = false;
        $LastCurlError = false;
        $LastHeadersReceived = false;
        $lastGETResponse = false;

        $LastGETImpl = "CURL";
        $lastGETResponse = Net::getCurl($url, $header);
        if ( $lastGETResponse !== false ) return $lastGETResponse;
        $LastGETImpl = "Stream";
        $lastGETResponse = Net::getStream($url, $header);
        if ( $lastGETResponse !== false ) return $lastGETResponse;
        error_log("Unable to GET Url=$url");
        error_log("Header: $header");
        throw new \Exception("Unable to GET url=".$url);
    }

    public static function getStream($url, $header=false) {
        $params = array('http' => array(
            'method' => 'GET',
            'header' => $header
            ));

        $ctx = stream_context_create($params);
        try {
            $response = file_get_contents($url, false, $ctx);
        } catch (Exception $e) {
            return false;
        }
        return $response;
    }

    // Note - handles port numbers in URL automatically
    public static function getCurl($url, $header=false) {
      if ( ! function_exists('curl_init') ) return false;
      global $last_http_response;
      global $LastCurlError;
      global $LastHeadersSent;
      global $LastHeadersReceived;

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);

      // Make sure that the header is an array and pitch white space
      $LastHeadersSent = trim($header);
      $header = explode("\n", trim($header));
      $htrim = Array();
      foreach ( $header as $h ) {
        $htrim[] = trim($h);
      }
      curl_setopt ($ch, CURLOPT_HTTPHEADER, $htrim);

      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); // ask for results to be returned
      curl_setopt($ch, CURLOPT_HEADER, 1);

      // Thanks to more and more PHP's not shipping with CA's installed
      // This becomes necessary
      if ( self::$VERIFY_PEER ) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
      } else {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
      }

      // Send to remote and return data to caller.
      $result = curl_exec($ch);
      if ( $result === false ) {
              $LastCurlError = curl_error($ch);
      }
      $info = curl_getinfo($ch);
      $last_http_response = $info['http_code'];
      $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
      $LastHeadersReceived = substr($result, 0, $header_size);
      $body = substr($result, $header_size);
      if ( $body === false ) $body = "";
      curl_close($ch);
      return $body;
    }

    public static function getBodySentDebug() {
        global $LastBODYURL;
        global $LastBODYMethod;
        global $LastBODYImpl;
        global $LastHeadersSent;

        $ret = $LastBODYMethod . " Used: " . $LastBODYImpl . "\n" .
             $LastBODYURL . "\n\n" .
             $LastHeadersSent . "\n";
        return $ret;
    }

    public static function getBodyReceivedDebug() {
        global $LastBODYURL;
        global $LastBODYMethod;
        global $LastBODYImpl;
        global $LastHeadersReceived;
        global $last_http_response;
        global $LastCurlError;

        $ret = $LastBODYMethod . " Used: " . $LastBODYImpl . "\n" .
             $LastBODYURL . "\n" .
             (is_string($LastCurlError) ? "Curl Error: " . $LastCurlError . "\n" : ' ').
             "HTTP Response Code: " . $last_http_response . "\n" .
             $LastHeadersReceived . "\n";
        return $ret;
    }

    public static function getGetSentDebug() {
        global $LastGETImpl;
        global $LastGETURL;
        global $LastHeadersSent;

        $ret = "GET Used: " . $LastGETImpl . "\n" .
             $LastGETURL . "\n\n" .
             $LastHeadersSent . "\n";
        return $ret;
    }

    public static function getGetReceivedDebug() {
        global $LastGETURL;
        global $last_http_response;
        global $LastCurlError;
        global $LastGETImpl;
        global $LastHeadersReceived;

        $ret = "GET Used: " . $LastGETImpl . "\n" .
             $LastGETURL . "\n" .
             (is_string($LastCurlError) ? "Curl Error: " . $LastCurlError . "\n" : ' ').
             "HTTP Response: " . $last_http_response . "\n" .
             $LastHeadersReceived . "\n";
        return $ret;
    }

    // Sadly this tries several approaches depending on
    // the PHP version and configuration.  You can use only one
    // if you know what version of PHP is working and how it will be
    // configured...
    public static function doBody($url, $method, $body, $header) {
        global $LastBODYURL;
        global $LastBODYMethod;
        global $LastBODYImpl;
        global $LastHeadersSent;
        global $last_http_response;
        global $LastCurlError;
        global $LastHeadersReceived;
        global $LastBODYContent;

        $LastBODYURL = $url;
        $LastBODYMethod = $method;
        $LastBODYImpl = false;
        $LastHeadersSent = false;
        $last_http_response = false;
        $LastHeadersReceived = false;
        $LastBODYContent = false;

        // Prefer curl because it checks if it works before trying
        $LastBODYContent = NET::bodyCurl($url, $method, $body, $header);
        $LastBODYImpl = "CURL";
        if ( $LastBODYContent !== false ) return $LastBODYContent;
        $LastBODYContent = NET::bodySocket($url, $method, $body, $header);
        $LastBODYImpl = "Socket";
        if ( $LastBODYContent !== false ) return $LastBODYContent;
        $LastBODYContent = NET::bodyStream($url, $method, $body, $header);
        $LastBODYImpl = "Stream";
        if ( $LastBODYContent !== false ) return $LastBODYContent;
        $LastBODYImpl = "Error";
        error_log("Unable to $method Url=$url");
        error_log("Header: $header");
        error_log("Body: $body");
        throw new \Exception("Unable to $method $url");
    }

    // From: http://php.net/manual/en/function.file-get-contents.php
    public static function bodySocket($endpoint, $method, $data, $moreheaders=false) {
      if ( ! function_exists('fsockopen') ) return false;
      if ( ! function_exists('stream_get_transports') ) return false;
        $url = parse_url($endpoint);

        if (!isset($url['port'])) {
          if ($url['scheme'] == 'http') { $url['port']=80; }
          elseif ($url['scheme'] == 'https') { $url['port']=443; }
        }

        $url['query']=isset($url['query'])?$url['query']:'';

        $hostport = ':'.$url['port'];
        if ($url['scheme'] == 'http' && $hostport == ':80' ) $hostport = '';
        if ($url['scheme'] == 'https' && $hostport == ':443' ) $hostport = '';

        $url['protocol']=$url['scheme'].'://';
        $eol="\r\n";

        $uri = "/";
        if ( isset($url['path'])) $uri = $url['path'];
        if ( U::strlen($url['query']) > 0 ) $uri .= '?'.$url['query'];
        if ( U::strlen($url['fragment']) > 0 ) $uri .= '#'.$url['fragment'];

        $headers =  $method." ".$uri." HTTP/1.0".$eol.
                    "Host: ".$url['host'].$hostport.$eol.
                    "Referer: ".$url['protocol'].$url['host'].$url['path'].$eol.
                    "Content-Length: ".strlen($data).$eol;
        if ( is_string($moreheaders) ) $headers .= $moreheaders;
        $len = U::strlen($headers);
        if ( substr($headers,$len-2) != $eol ) {
            $headers .= $eol;
        }
        $headers .= $eol.$data;
        // echo("\n"); echo($headers); echo("\n");
        // echo("PORT=".$url['port']);
        $hostname = $url['host'];
        if ( $url['port'] == 443 ) $hostname = "ssl://" . $hostname;
        try {
            $fp = fsockopen($hostname, $url['port'], $errno, $errstr, 30);
            if($fp) {
                fputs($fp, $headers);
                $result = '';
                while(!feof($fp)) { $result .= fgets($fp, 128); }
                fclose($fp);
                // removes HTTP response headers
                $pattern="/^.*\r\n\r\n/s";
                $result=preg_replace($pattern,'',$result);
                return $result;
            }
        } catch(Exception $e) {
            return false;
        }
        return false;
    }

    public static function bodyStream($url, $method, $body, $header) {
        $params = array('http' => array(
            'method' => $method,
            'content' => $body,
            'header' => $header
            ));

        $ctx = stream_context_create($params);
        try {
            $fp = @fopen($url, 'r', false, $ctx);
            $response = @stream_get_contents($fp);
        } catch (Exception $e) {
            return false;
        }
        return $response;
    }

    // Note - handles port numbers in URL automatically
    public static function bodyCurl($url, $method, $body, $header) {
      if ( ! function_exists('curl_init') ) return false;
      global $last_http_response;
      global $LastCurlError;
      global $LastHeadersSent;
      global $LastHeadersReceived;
      global $LastBODYImpl;
      global $LastBODYMethod;
      global $LastBODYContent;

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);

      // Make sure that the header is an array and pitch white space
      $LastHeadersSent = trim($header);
      $header = explode("\n", trim($header));
      $htrim = Array();
      foreach ( $header as $h ) {
        $htrim[] = trim($h);
      }
      curl_setopt ($ch, CURLOPT_HTTPHEADER, $htrim);

      if ( $method == "POST" ) {
        curl_setopt($ch, CURLOPT_POST, 1);
      } else {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
      }

      curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); // ask for results to be returned
      curl_setopt($ch, CURLOPT_HEADER, 1);

      // Thanks to more and more PHP's not shipping with CA's installed
      // This becomes necessary
      if ( static::$VERIFY_PEER ) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
      } else {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
      }

      // Send to remote and return data to caller.
      $result = curl_exec($ch);
      if ( $result === false ) {
          $LastCurlError = curl_error($ch);
      }
      $info = curl_getinfo($ch);
      $last_http_response = $info['http_code'];
      if(curl_errno($ch))
      {
          error_log('Curl error: ' . curl_error($ch));
      }
      $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
      $LastHeadersReceived = substr($result, 0, $header_size);
      $body = substr($result, $header_size);
      if ( $body === false ) $body = ''; // Handle empty body
      curl_close($ch);
      $LastBODYContent = $body;
      $LastBODYImpl = "CURL";
      $LastBODYMethod = $method;
      return $body;
    }

    /**
     * Send a 403 header
     */
    public static function send403($msg=null, $detail=null) {
        if ( headers_sent() ) {
            echo("Headers sent - they would be:\n");
            echo("HTTP/1.1 403 Forbidden"."\n");
            if ( is_string($msg) ) echo("X-Error-Message: ".$msg."\n");
            if ( is_string($detail) ) echo("X-Error-Detail: ".$detail."\n");
        } else {
            header("HTTP/1.1 403 Forbidden");
            if ( is_string($msg) ) header("X-Error-Message: ".$msg);
            if ( is_string($detail) ) header("X-Error-Detail: ".$detail);
        }
    }

    /**
     * Send a 400 (Malformed request) header
     */
    public static function send400($msg='Malformed request', $detail=null) {
        if ( headers_sent() ) {
            echo("Headers sent - they would be:\n");
            echo("HTTP/1.1 400 ".$msg."\n");
            if ( is_string($detail) ) echo("X-Error-Detail: ".$detail."\n");
        } else {
            header("HTTP/1.1 400 ".$msg);
            if ( is_string($detail) ) header("X-Error-Detail: ".$detail);
        }
    }

    /**
     * Get the actual IP address of the incoming request.
     *
     * Handle being behind a load balancer or a proxy like Cloudflare.
     * This will often return NULL when talking to localhost to make sure
     * to test code using this on a real IP address.
     *
     * Adapted from: https://www.chriswiegman.com/2014/05/getting-correct-ip-address-php/
     * With some additional explode goodness via: http://stackoverflow.com/a/25193833/1994792
     *
     * @return string The IP address of the incoming request or NULL if it cannot be determined.
     */
    public static function getIP() {

        global $CFG;

        //Just get the headers if we can or else use the SERVER global
        if ( function_exists( 'apache_request_headers' ) ) {
            $rawheaders = apache_request_headers();
        } else {
            $rawheaders = $_SERVER;
        }

        // Lower case headers
        $headers = array();
        foreach($rawheaders as $key => $value) {
            $key = trim(strtolower($key));
            if ( !is_string($key) || empty($key) ) continue;
            $headers[$key] = $value;
        }

        // $filter_option = FILTER_FLAG_IPV4;
        // $filter_option = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        $filter_option = 0;

        $the_ip = false;

        // When not behind proxy, trust IP from web server over headers
        if ( $CFG->trust_forwarded_ip === false && array_key_exists( 'REMOTE_ADDR', $_SERVER ) ) {
            $the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, $filter_option );
        }

        // Check Cloudflare headers
        if ( $the_ip === false && array_key_exists( 'http_cf_connecting_ip', $headers ) ) {
            $pieces = explode(',',$headers['http_cf_connecting_ip']);
            $the_ip = filter_var(current($pieces),FILTER_VALIDATE_IP, $filter_option );
        }

        if ( $the_ip === false && array_key_exists( 'cf-connecting-ip', $headers ) ) {
            $pieces = explode(',',$headers['cf-connecting-ip']);
            $the_ip = filter_var(current($pieces),FILTER_VALIDATE_IP, $filter_option );
        }

        // Get the forwarded IP from more traditional places
        if ( $the_ip == false && array_key_exists( 'x-forwarded-for', $headers ) ) {
            $pieces = explode(',',$headers['x-forwarded-for']);
            $the_ip = filter_var(current($pieces),FILTER_VALIDATE_IP, $filter_option );
        }

        if ( $the_ip === false && array_key_exists( 'http_x_forwarded_for', $headers ) ) {
            $pieces = explode(',',$headers['http_x_forwarded_for']);
            $the_ip = filter_var(current($pieces),FILTER_VALIDATE_IP, $filter_option );
        }

        if ( $the_ip === false && array_key_exists( 'remote_addr', $headers ) ) {
            $the_ip = filter_var( $headers['remote_addr'], FILTER_VALIDATE_IP, $filter_option );
        }

        // Fall through and get *something*
        if ( $the_ip === false && array_key_exists( 'REMOTE_ADDR', $_SERVER ) ) {
            $the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, $filter_option );
        }

        if ( $the_ip === false ) $the_ip = NULL;
        return $the_ip;
    }

    /**
     * Return the IP Address of the current server
     */
    // https://stackoverflow.com/questions/3219178/php-how-to-get-local-ip-of-system
    public static function serverIP() {
        return getHostByName(getHostName());
    }

    /**
     * Return true if we have a routable address
     */
    // https://stackoverflow.com/questions/13818064/check-if-an-ip-address-is-private
    public static function isRoutable($ipaddr) {
        return $ipaddr == filter_var(
            $ipaddr,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE |  FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Return true if the http code is 2xx (success)
     */
    public static function httpSuccess($httpcode) {
        return ($httpcode >= 200) && ($httpcode < 300);
    }

    /**
     * Put as much oomph into setting a cookie as we can
     */
    public static function setCookieStrong($name, $value, $domain, $expires) {
        $old_value = U::get($_COOKIE, $name);
        if (is_string($old_value) && U::strlen($old_value) > 1 ) {
            if ( $old_value == $value ) return;
        } else {
            setcookie(
                $name,
                $value,
                [
                    'expires' => $expires,
                    'path' => '/',
                    'domain' => $domain,
                    'samesite' => 'None',
                    'secure' => true,
                ]
            );
        }
    }

}
