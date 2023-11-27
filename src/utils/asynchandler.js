const asynchandler = (requesthandler) => {
    return (req, res, next) => {
        Promise.resolve(requesthandler(req, res, next))
        .catch((err) => next(err));
    }
}

export { asynchandler }


// const asynchandler = (fn) => async (req, res, next) => {
//     try {

//     } catch (error) {
//         res.status(err.code || 500).json({
//             sucess: false,
//             message: err.message
//         })

//     }
// }