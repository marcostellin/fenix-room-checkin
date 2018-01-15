        $(document).ready( function (){

            $(".date").each( function (index){


                utcTime = $(this).html();
                var locale = moment.utc(utcTime).local().format('DD-MM-YYYY HH:mm:ss');
                $(this).html(locale);

            });
        });
