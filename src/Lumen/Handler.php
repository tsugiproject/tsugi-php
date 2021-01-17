<?php

namespace Laravel\Lumen\Exceptions;

use Laravel\Lumen\Exceptions\LumenHandler;

use Illuminate\Http\Response;

use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

use Tsugi\UI\Output;

/**
 * This is a hack of extreme magnitude which I wish were simpler
 *
 * Since the Lumen run-time is hard coded to load the 
 * Laravel\Lumen\Exceptions\Handler to handle exceptions we are
 * going to jump infront of the one that comes from Lumen.
 * We copy the Handler form Lumen as LumenHandler and make it 
 * our parent class so we can extend one method (for now)
 * to customize the response for a 404.
 *
 * I would love to fins a way to use the Container bindings to perform
 * this trick.  But I have not dug through them.
 */

class Handler extends LumenHandler {

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $e
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Exception
     */
    public function render($request, \Exception $e)
    {
        global $CFG, $OUTPUT;
        if ($e instanceof \Symfony\Component\HttpKernel\Exception\NotFoundHttpException ) {
            $OUTPUT->buffer = true;
            $txt = $OUTPUT->header();
            $txt .= $OUTPUT->bodyStart();
            $txt .= $OUTPUT->topNav();
            $txt .= '<h1>';
            $txt .= __('Not Found');
            $txt .= '</h1>';
            $txt .= $OUTPUT->footer();
            return new Response($txt, 404);
        }

        return parent::render($request, $e);
    }
}
