#!/bin/bash
#
# ratproxy - report generator
# ---------------------------
#
# This is essentially a prettyprinter for ratproxy logs. It removes
# dupes, sorts entries within groups, then sorts groups base don highest
# priority within the group, and produces some nice HTML with form replay
# capabilities.
#
# TODO: Use standalone stylesheets to conserve bytes.
#
# Author: Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2007, 2008 by Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [ "$1" = "" ]; then
  echo "Usage: $0 ratproxy.log" 1>&2
  exit 1
fi

if [ ! -f "$1" ]; then
  echo "Input file not found." 1>&2
  exit 1
fi

test "$RAT_URLPREFIX" = "" || RAT_URLPREFIX="/$RAT_URLPREFIX/"

# Output prologue...

cat <<_EOF_
<html>

<head>
<meta http-equiv="Content-Type" content="text/plain; charset=iso-8859-1">
<title>ratproxy - security testing proxy</title>
<style>
a:link, a:visited { text-decoration: none; color: green }
a:hover { text-decoration: underline; color: red }
body { background-color: white; background-image: url('ratproxy-back.png'); background-repeat: no-repeat; }
</style>
</head>

<body>

<div style="width: 60%">
<span style="float: left; height: 190px; width: 350px"></span>

<font face="arial,helvetica" size=+0>
<b>Ratproxy audit report</b>
<p>
<font size=-1>
Generated on: <b>`date +'%Y/%m/%d %H:%M'`</b><br>
Input file: <b>$1</b>
</font>
<p>
<font color="crimson" size=-1>NOTE: Not all of the issues reported necessarily
correspond to actual security flaws. Findings should be validated
by manual testing and analysis where appropriate. When in doubt,
<a href="mailto:lcamtuf@google.com">contact the author</a>.</font>
<br clear=all>

<hr size=1 color=black>
<p>
<font size=-1>
<div style="border: 1px solid teal; background-color: white">
<b>Report risk and risk modifier designations:</b>
<table border=0>
<tr>
<td width=25%>
<font face="Bitstream Vera Sans Mono,Andale Mono,lucida console" size=-2>
<span style="border: solid black 1px; background-color: blue; color: white; padding: 0.1em 0.4em 0.1em 0.4em"><b>LOW</b></span>
to
<span style="border: solid black 1px; background-color: crimson; color: white; padding: 0.1em 0.4em 0.1em 0.4em"><b>HIGH</b></span>
</td>
<td><font size=-1>Issue urgency classification (composite of impact and identification accuracy)</font></td>
</tr>
<tr>
<td width=25%>
<font face="Bitstream Vera Sans Mono,Andale Mono,lucida console" size=-2>
<span style="border: solid black 1px; background-color: gray; color: white; padding: 0.1em 0.4em 0.1em 0.4em"><b>INFO</b></span>
</td>
<td><font size=-1>Non-discriminatory entry for further analysis</font></td>
</tr>
<tr>
<td width=25%>
<font face="Bitstream Vera Sans Mono,Andale Mono,lucida console" size=-2>
<span style="border: solid gray 1px; background-color: #fffece; color: #800000; padding: 0.1em 0.4em 0.1em 0.4em">ECHO</span>
/
<span style="border: solid gray 1px; background-color: #fffece; color: #A0A080; padding: 0.1em 0.4em 0.1em 0.4em">echo</span>
</font>
</td>
<td><font size=-1>Query parameters echoed back / not echoed in HTTP response, respectively</font></td>
</tr>
<tr>
<td width=25%>
<font face="Bitstream Vera Sans Mono,Andale Mono,lucida console" size=-2>
<span style="border: solid gray 1px; background-color: #fffece; color: #800000; padding: 0.1em 0.4em 0.1em 0.4em">PRED</span>
/
<span style="border: solid gray 1px; background-color: #fffece; color: #A0A080; padding: 0.1em 0.4em 0.1em 0.4em">pred</span>
</font>
</td>
<td><font size=-1>Request URL or query data likely is / is not predictable to third parties, respectively</font></td>
</tr>
<tr>
<td>
<font face="Bitstream Vera Sans Mono,Andale Mono,lucida console" size=-2>
<span style="border: solid gray 1px; background-color: #fffece; color: #800000; padding: 0.1em 0.4em 0.1em 0.4em">AUTH</span>
/
<span style="border: solid gray 1px; background-color: #fffece; color: #A0A080; padding: 0.1em 0.4em 0.1em 0.4em">auth</span>
</font>
</td>
<td><font size=-1>Request requires / does not require cookie authentication, respectively</font></td>
</tr>
</table>
</div>
</font>
<p>
<hr size=1 color=black>

<script>
function toggle(id) { 
  var i = document.getElementById(id);
  if (i.style.display == 'none') i.style.display = 'inline'; else i.style.display = 'none';
  i = document.getElementById('hid_' + id);
  if (i.style.display == 'none') i.style.display = 'inline'; else i.style.display = 'none';
}
</script>

<font face="arial,helvetica" size=-1>
<ul>
_EOF_

if [ ! -s "$1" ]; then
  echo "<b>No activity to report on found in log file."
  exit 1
fi

PREVDESC=X
CNT=0
SCNT=0

# So this is some nearly incomprehensible logic to sort entries by priorities,
# sort groups based on highest priority within a group, and then remove any
# duplicates (paying no attention to some fields, such as trace file location),
# group "offending value" fields, and more. At some point - too late in the
# game - it became painfully obvious that this should not be a shell script ;-)

( sort -t '|' -k 1,8 -k 10,100 -ru <"$1" | grep '^[0123]|' | sort -t '|' -k 3,3 -s | \
  awk -F'|' '{if ($3!=PF) { npri=$1;PF=$3; }; printf "%s-%s|%s\n", npri, $3, $0}' | \
  sort -r -k 1,1 -s | sed 's/|!All /|All /'; echo "Dummy EOF" ) | \
  awk -F'|' '{

               PTRM=TRM; PFR=FR; PTA=TA; 
               FR=""; TA=""; TRM=""; GOTVAL="";

               for (a=1;a<=NF;a++) { 
                 if (a < 5) { 
                   TRM=TRM "|" $a;
                   FR=FR $a "|";
                 } else if (a > 5) {
                   TRM=TRM "|" $a;
                   TA=TA "|" $a;
                 } else GOTVAL=$a;

               }

               if (PTRM == TRM) {
                 if (GOTVAL != "-") {
                   if (LIST == "-") LIST="<span style=\"background-color: #FFFFB0\">" GOTVAL "</span>";
                   else LIST=LIST ", <span style=\"background-color: #FFFFB0\">" GOTVAL "</span>";
                 }
               } else {
                 if (PTRM != "") print PFR LIST PTA;
                 if (GOTVAL == "-") LIST="-";
                 else LIST="<span style=\"background-color: #FFFFB0\">" GOTVAL "</span>";
               }

             }' | \
  while IFS="|" read -r skip severity modifier desc offend code len mime sniff cset trace method url cookies payload response; do

    # If issue name changed, output a new header, complete with fold / unfold controls.
    # Default groups with 'info' items only to folded state.

    if [ ! "$PREVDESC" = "$desc" ]; then

      SCNT=$[SCNT+1]

      if [ ! "$severity" = "0" ]; then

        echo "</ul></span><font size=+1><u>$desc</u></font>&nbsp;<font size=-2 color=gray>[<a href=\"javascript:void(0)\" onclick=\"toggle('list$SCNT')\">toggle</a>]</font>"
        echo "<span id=hid_list$SCNT style=\"display:none\"><br><br><font color=gray><i>Section hidden</i></font><p></p></span>"
        echo "<span id=list$SCNT style=\"display:inline\"><ul style=\"margin-top: 0px\"><font size=-2>"

      else

        echo "</ul></span><font size=+1><u>$desc</u></font>&nbsp;<font size=-2 color=gray>[<a href=\"javascript:void(0)\" onclick=\"toggle('list$SCNT')\">toggle</a>]</font>"
        echo "<span id=hid_list$SCNT style=\"display:inline\"><br><br><font color=gray><i>Section hidden</i></font><p></p></span>"
        echo "<span id=list$SCNT style=\"display:none\"><ul style=\"margin-top: 0px\"><font size=-2>"

      fi

      echo "<font color=darkslateblue>"
      grep -F "~$desc~" messages.list | cut -d'~' -f3 
      echo "</font></font><p>"

      PREVDESC="$desc"

    fi

    # Output severity data.

    echo -n "<li><font face=\"Bitstream Vera Sans Mono,Andale Mono,Lucida Console\" size=-2>"

    if [ "$severity" = "3" ]; then
      echo -n "<span style=\"border: solid black 1px; background-color: crimson; color: white; padding: 0.1em 0.4em 0.1em 0.4em\"><b>HIGH</b></span>"
    elif [ "$severity" = "2" ]; then
      echo -n  "<span style=\"border: solid black 1px; background-color: darkmagenta; color: white; padding: 0.1em 0.4em 0.1em 0.4em\"><b>MEDIUM</b></span>"
    elif [ "$severity" = "1" ]; then
      echo -n  "<span style=\"border: solid black 1px; background-color: blue; color: white; padding: 0.1em 0.4em 0.1em 0.4em\"><b>LOW</b></span>"
    else
      echo -n  "<span style=\"border: solid black 1px; background-color: gray; color: white; padding: 0.1em 0.4em 0.1em 0.4em\"><b>INFO</b></span>"
    fi

    # Provide additional flags on all but 'All visited URLs' sections.

    if [ ! "$desc" = "All visited URLs" ]; then

      echo -n "<span style=\"border: solid gray; border-width: 1px 1px 1px 0px; background-color: #fffece; color: #A0A040; padding: 0.1em 0.4em 0.1em 0.4em\">"

      if [ "$[modifier & 4]" = "0" ]; then
        echo -n "echo&nbsp;"
      else
        echo -n "<font color=\"#800000\">ECHO</font>&nbsp;"
      fi

      if [ "$[modifier & 1]" = "0" ]; then
        echo -n "pred&nbsp;"
      else
        echo -n "<font color=\"#800000\">PRED</font>&nbsp;"
      fi

      if [ "$[modifier & 2]" = "0" ]; then
        echo -n "auth"
      else
        echo -n "<font color=\"#800000\">AUTH</font>"
      fi

      echo -n "</span>&nbsp;"

    else

      echo -n "&nbsp;"

    fi

    # Prepare trace / decompile links, if available.

    if [ "$trace" = "-" ]; then
      TLINK=""
    else

      if [ -s "$trace.flr" ]; then
        TLINK="&nbsp;<font size=-2>[<a href=\"$RAT_URLPREFIX$trace.flr\">decompile</a>]&nbsp;[<a href=\"$RAT_URLPREFIX$trace\">view&nbsp;trace</a>]</font>"
      else
        TLINK="&nbsp;<font size=-2>[<a href=\"$RAT_URLPREFIX$trace\">view&nbsp;trace</a>]</font>"
      fi

    fi

    # Output URL, query, and response data.

    test "$method" = "-" && method="[Referer]"

    if [ "$payload" = "-" ]; then

      echo "<font color=\"teal\">$method</font>&nbsp;<a href=\"$url\">$url</a>&nbsp;&rArr;&nbsp;$code$TLINK<br>"

      if [ ! "$response" = "-" ]; then
        echo "<font size=-3 color=gray>Response&nbsp;($len):&nbsp;$response</font><br>"
      fi

      if [ ! "$cookies" = "-" ]; then
        echo "<font size=-3 color=royalblue>Cookies&nbsp;set:&nbsp;$cookies</font><br>"
      fi

      if [ ! "$offend" = "-" ]; then
        echo "<font size=-3 color=darkred>Offending&nbsp;value:&nbsp;$offend</font><br>"
      fi

      if [ "$method" = "[Referer]" ]; then
        echo "<font size=-3 color=black>Target&nbsp;resource:&nbsp;<a href=\"$sniff\">$sniff</a></font>"
      else
        echo "<font size=-3 color=black>MIME type: <font color=teal>$mime</font>, detected: <font color=teal>$sniff</font>, charset: <font color=teal>$cset</font></font>"
      fi

    else

      isfile=""

      if echo "$payload" | grep -qF "=FILE["; then
        isfile="(FILE)&nbsp;"
      fi

      echo "<font color=\"crimson\">$isfile$method</font>&nbsp;<a href=\"javascript:void(0)\" onclick=\"document.getElementById('form$CNT').submit();return false;\">$url</a>&nbsp;&rArr;&nbsp;$code$TLINK<br>"
      echo "<font size=-3 color=teal>Payload:&nbsp;$payload</font><br>"

      if [ ! "$response" = "-" ]; then
        echo "<font size=-3 color=gray>Response&nbsp;($len):&nbsp;$response</font><br>"
      fi

      if [ ! "$cookies" = "-" ]; then
        echo "<font size=-3 color=royalblue>Cookies&nbsp;set:&nbsp;$cookies</font><br>"
      fi

      if [ ! "$offend" = "-" ]; then
        echo "<font size=-3 color=darkred>Offending&nbsp;value:&nbsp;$offend</font><br>"
      fi

      echo "<font size=-3 color=black>MIME type: <font color=teal>$mime</font>, detected: <font color=teal>$sniff</font>, charset: <font color=teal>$cset</font></font><br>"

      if ! echo "$payload" | grep -q '^GWT_RPC\['; then
  
        echo "<input type=submit value=\"edit values\" onclick=\"document.getElementById('form$CNT').style.display='inline';return false;\" style=\"border-width: 1px; background-color: #FFFFC0; font-size: 0.9em; display: inline\">"
        echo "<form action=\"$url\" method=\"POST\" id=\"form$CNT\" style=\"display: none\">"
        echo "$payload" | sed 's/\&#x\(..\);/%\1/g' | sed 's/&/\
/g' | sed 's/%26/\&/g;s/%3B/;/g' | sed 's/\%\(..\)/\&#x\1;/g' | \
        while IFS='=' read -r param val; do 
          echo "<INPUT TYPE=text STYLE=\"border-width: 1px; background-color: #FFC0A0; font-size: 0.9em\" NAME=\"$param\" VALUE=\"$val\">"
        done
        echo "</form>"

      fi

    fi

    echo "</font><p></li>"

    CNT=$[CNT+1]

  done

echo "</ul></div></body></html>"
