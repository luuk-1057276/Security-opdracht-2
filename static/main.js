let navBarOpen = false;

$(document).ready(function() {


    function updateAdminDashboard() {
        $.ajax({
            url: "/admin/update_dashboard",
            type: "GET",
            success: function(data) {
                $("#researchCount").text(data.research_count + " onderzoeken");
                $("#researchSignupRequestCount").text(data.research_signup_request_count + " aanvragen");
                $("#userCount").text(data.user_count + " gebruikers");
            },
            error: function(xhr, status, error) {
                console.error("Error updating dashboard");
                console.log(xhr, status, error);
            }

        })
    }

    if (window.location.href === "http://127.0.0.1:5000/admin/") {
        updateAdminDashboard();
        setInterval(updateAdminDashboard, 5000);
    };



    function updateApproveResearchRequests() {
        $.ajax({
            url: "/admin/update_approve_research_requests",
            type: "GET",
            success: function(data) {
                $("#approveResearchRequestList").empty();
                data.research_signup_requests.forEach(function(data) {
                    $("#approveResearchRequestList").append(`
                        <div class="col-4" data-user="${data.firstname} ${data.infix} ${data.lastname}" data-research="${data.title}" data-status="${data.status}">
                            <div class="card padding-bottom">
                                <div class="card-header">
                                    <h5 class="card-title">status : ${data.status}</h5>
                                </div>
                                <div class="card-body">
                                    <p class="card-text">Gebruiker: ${data.firstname} ${data.infix ? data.infix : ''} ${data.lastname}</p>
                                    <p class="card-text">Onderzoek: ${data.title}</p>
                                    <form action="/admin/approve_research_requests" method="post">
                                        <button class="btn btn-primary" type="submit" name="research_id" value="${data.id}">details bekijken</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    `);

                    //nadat de content is gegenereert, worden deze functies ingeroepen
                    //om de kleur van de header te updaten, en om ervoor te zorgen
                    //dat de filter functie niet breekt
                    updateCardHeaderColor();
                    filterApproveResearchRequestList()
    
                });
                
            },
            error: function(xhr, status, error) {
                console.error("Error updating approve research requests");
                console.log(xhr, status, error);
            }

        })
    }
    //de functie om de pagina automatisch te verversen wordt alleen
    //gecalled op de pagina waar dat nodig is, om errors te voorkomen
    if (window.location.href === "http://127.0.0.1:5000/admin/approve_research_requests") {
        updateApproveResearchRequests()
        setInterval(updateApproveResearchRequests, 5000);
    };



    if (window.location.href === "http://127.0.0.1:5000/approve_research_requests") {
        filterApproveResearchRequestList();
    };

    
    $(".extra_details").hide();
    $(".less_details_button").hide();
    $(".more_details_button").show();
    $(".delete_research").hide();

    $(".more_details_button").click(function() {
        $(".extra_details[data-id='" + $(this).data("id") + "']").show();
        $(".less_details_button[data-id='" + $(this).data("id") + "']").show();
        $(".more_details_button[data-id='" + $(this).data("id") + "']").hide();
    });

    $(".less_details_button").click(function() {
        $(".extra_details[data-id='" + $(this).data("id") + "']").hide();
        $(".less_details_button[data-id='" + $(this).data("id") + "']").hide();
        $(".more_details_button[data-id='" + $(this).data("id") + "']").show();
    });


    $(".deleteResearchButton").click(function() {
        $(".delete_research[data-id='" + $(this).data("id") + "']").show();
        $(".deleteResearchButton[data-id='" + $(this).data("id") + "']").hide();
    });

    $(".cancelDelete").click(function() {
        $(".delete_research[data-id='" + $(this).data("id") + "']").hide();
        $(".deleteResearchButton[data-id='" + $(this).data("id") + "']").show();
    });




    $("#openNavbar").click(function() {
        if (navBarOpen) {
            $(".nav_box").animate({left: '-30%'}, { queue: false }, 300);
            $(".open_navbar").animate({opacity: '1'}, { queue: false }, 100);
            $(".collapse_navbar").animate({opacity: '0'}, { queue: false }, 100);
            $(".open_navbar").animate({rotate: '0deg'}, { queue: false }, 100);
            $(".collapse_navbar").animate({rotate: '0deg'}, { queue: false }, 100);
            navBarOpen = false;
        }

        else {
            $(".nav_box").animate({left: '0%'}, { queue: false }, 300);
            $(".open_navbar").animate({opacity: '0'}, { queue: false }, 100);
            $(".collapse_navbar").animate({opacity: '1'}, { queue: false }, 100);
            $(".open_navbar").animate({rotate: '180deg'}, { queue: false }, 100);
            $(".collapse_navbar").animate({rotate: '180deg'}, { queue: false }, 100);
            navBarOpen = true;
        };
        
    });


    $("#searchTitle, #searchOrganisation, #searchType, #searchDate").on("input", filterResearchList); 
    $("#searchUser, #searchResearch, #searchStatus").on("input", filterApproveResearchRequestList);
    $("#searchApproveTitle, #searchApproveOrganisation").on("input", filterApproveResearchList);
    $("#searchUserType, #searchFirstName, #searchLastName, #searchEmail, #searchPhoneNumber").on("input", filterUserList);

    //wordt gebruikt bij research_list, my_registered_researches, list_of_researches
    function filterResearchList() {
        let filterTitle = $("#searchTitle").val().toLowerCase();
        let filterOrganisation = $("#searchOrganisation").val().toLowerCase();
        let filterType = $("#searchType").val().toLowerCase();
        let searchDate = $("#searchDate").val() ? new Date($("#searchDate").val()) : null;
        

        $("#researchList .col-4").each(function() {
            let title = $(this).data("title").toString().toLowerCase();
            let organisation = $(this).data("organisation").toString().toLowerCase();
            let type = $(this).data("type").toString().toLowerCase();
            let availableFrom = new Date($(this).data("availableFrom"));
            let availableUntil = new Date($(this).data("availableUntil"));
            let showItem = title.includes(filterTitle) && organisation.includes(filterOrganisation) && type.includes(filterType);
            console.log(filterType, type)
            if (searchDate !=null) {
                showItem = showItem && searchDate >= availableFrom && searchDate <= availableUntil;
            }

            $(this).toggle(showItem);

        });

    };
    //wordt gebruikt bij approve_research_requests
    function filterApproveResearchRequestList() {
        let filterUser = $("#searchUser").val().toLowerCase();
        let filterResearch = $("#searchResearch").val().toLowerCase();
        let filterStatus = $("#searchStatus").val().toLowerCase();

        $("#approveResearchRequestList .col-4").each(function() {
            let user = $(this).data("user").toString().toLowerCase();
            let research = $(this).data("research").toString().toLowerCase();
            let status = $(this).data("status").toString().toLowerCase();
            let showItem = user.includes(filterUser) && research.includes(filterResearch) && status.includes(filterStatus);
            $(this).toggle(showItem);

        });
    };
    //wordt gebruikt bij approve_research
    function filterApproveResearchList() {
        let filterApproveTitle = $("#searchApproveTitle").val().toLowerCase();
        let filterApproveOrganisation = $("#searchApproveOrganisation").val().toLowerCase();

        $("#approveResearchList li").each(function() {
            let title = $(this).data("title").toString().toLowerCase();
            let organisation = $(this).data("organisation").toString().toLowerCase();
            let showItem = title.includes(filterApproveTitle) && organisation.includes(filterApproveOrganisation);
            $(this).toggle(showItem);

        });
    };

    //wordt gebruikt bij list_of_users
    function filterUserList() {
        let filterUserType = $("#searchUserType").val().toLowerCase();
        let filterFirstName = $("#searchFirstName").val().toLowerCase();
        let filterLastName = $("#searchLastName").val().toLowerCase();
        let filterEmail = $("#searchEmail").val().toLowerCase();
        let filterPhoneNumber = $("#searchPhoneNumber").val().toLowerCase();

        $("#userList li").each(function() {
            let userType = $(this).data("userType").toString().toLowerCase();
            let firstName = $(this).data("firstName").toString().toLowerCase();
            let lastName = $(this).data("lastName").toString().toLowerCase();
            let email = $(this).data("email").toString().toLowerCase();
            let phoneNumber = $(this).data("phoneNumber").toString().toLowerCase();
            let showItem = userType.includes(filterUserType) && firstName.includes(filterFirstName) && lastName.includes(filterLastName) && email.includes(filterEmail) && phoneNumber.includes(filterPhoneNumber);
            $(this).toggle(showItem);

        });
    }

    $("#clearSearchFields").click(function() {
        $("#searchTitle, #searchOrganisation, #searchType, #searchDate").val('');
        $('#researchList li').show();

        $("#searchUser, #searchResearch").val('');
        $("#searchStatus").val('in afwachting')
        filterApproveResearchRequestList();

        $("#searchApproveTitle, #searchApproveOrganisation").val('');
        $('#approveResearchList li').show();

        $("#searchUserType, #searchFirstName, #searchLastName, #searchEmail, #searchPhoneNumber").val('');
        $('#userList li').show();
    });
        

    function updateCardHeaderColor() {
        $("div[data-status]").each(function() {
            var status = $(this).data("status");
            var cardHeader = $(this).find('.card-header');
            switch (status) {
                case 'goedgekeurd':
                    cardHeader.css('background-color', 'rgb(141, 247, 141)');
                    break;
                case 'afgekeurd':
                    cardHeader.css('background-color', 'rgb(252, 139, 139)');
                    break;
                case 'in afwachting':
                    cardHeader.css('background-color', 'rgb(247, 209, 139)');
                    break;
                default:
                    cardHeader.css('background-color', 'gray');
            }
        });
    }

    if (window.location.href === "http://127.0.0.1:5000/register") {
        document.getElementById('toggleButton').onclick = function() {
            console.log('clicked');
        let hiddenInfo = document.getElementById('hiddenInfo');
        if (hiddenInfo.style.display === 'none') {
            hiddenInfo.style.display = 'block';
        } else {
            hiddenInfo.style.display = 'none';
        }
        };
    };



});