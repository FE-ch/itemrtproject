/* Register button loading */
$('#register_btn').click(function() {
    /* Change to loading state */
    $(this).button('loading');
 });

/* Submitting practice button loading */
$('#practicesubmitbtn').click(function() {
    /* Change to loading state */
    $(this).button('loading');
 });

/* Submitting feedback button loading */
$('#feedback_btn').click(function() {
    /* Change to loading state */
    $(this).button('loading');
 });

/* Extend the sidebar to length of the rest of the elements */
if($('#practicecontentend').length) {
    var sidebar = $("#practicesidebar");
    var contentend = $('#practicecontentend');

    var pos_sidebar = sidebar.offset();
    var pos_contentend = contentend.offset();

    /* Get calculated minimum height of sidebar and update */
    var sidebar_height = pos_contentend.top - pos_sidebar.top;

    if(sidebar.height() < sidebar_height) {
        sidebar.height(sidebar_height);
    }
}

/* Google Code prettify! */
!function ($) {
    $(function(){
        window.prettyPrint && prettyPrint()
    })
}(window.jQuery)

/* Extend the answer options to same height (tallest) */
if($('#acontent').length) {
    var ans_a = $("#acontent_a");
    var ans_b = $("#acontent_b");
    var ans_c = $("#acontent_c");
    var ans_d = $("#acontent_d");

    tallest_height = Math.max(ans_a.outerHeight(), ans_b.outerHeight(), ans_c.outerHeight(), ans_d.outerHeight());

    /* Update height to all elements */
    ans_a.height(tallest_height);
    ans_b.height(tallest_height);
    ans_c.height(tallest_height);
    ans_d.height(tallest_height);
}

/* AJAX comments posting */
(function( $ ){
$.fn.bindPostCommentHandler = function() {
    // We get passed a list of forms; iterate and get a unique id for each
    // attach a submit trigger to handle saving and returning
    this.each(function() {
        //$(this).find('input.submit-preview').remove();
        $(this).submit(function() {
            commentform = this;
            commentwrap = $(this).parent();
            $.ajax({
                type: "POST",
                data: $(commentform).serialize(),
                url: $(commentform).attr('action'),
                cache: false,
                dataType: "html",
                success: function(html, textStatus) {
                    $(commentform).replaceWith(html);
                    $(commentwrap).hide();
                    $(commentwrap).slideDown(600);
                    $(commentwrap).find('form').bindPostCommentHandler();
                },
                error: function (XMLHttpRequest, textStatus, errorThrown) {
                    $(commentform).replaceWith('Your comment was unable to be posted at this time.  We apologise for the inconvenience.');
                }
            });
            return false;
        });
    }); //each
};
})( jQuery );

(function( $ ){
$.fn.bindReplyButtonHandler = function() {
    // We get passed a list of buttons; iterate and set each to show the form (which was hidden)
    this.each(function() {
        $(this).click(function() {
            /* Show the form! */
            replybutton = this;
            replyform = "#" + $(replybutton).val();
            $(replyform).show();

            return false;
        });
    }); //each
};
})( jQuery );

$(function() {
    $('.comment-form form').bindPostCommentHandler();
    $('.comment-reply-btn').bindReplyButtonHandler();
});

/* Scrollspy init */
$('body').scrollspy({target: '.bs-sidenav'});

/* THIS IS NOT SUPPOSED TO BE HERE !*/
if(typeof(loadChart) === "function") {
    loadChart();
}