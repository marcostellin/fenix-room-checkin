 $(document).ready(function worker() {
 
            $.getJSON("/user/ajax/messages", function(resp){

                    alertify.alert("Message from " + resp["from"], resp["content"],
                    function (){
                       $.post("/user/ajax/messages", {read:"True"});
                    })
                    .always(function (){
                       setTimeout(worker, 5000);
                    });
                
            });
           
});
