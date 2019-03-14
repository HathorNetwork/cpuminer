#!/bin/sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# receive tag as argument
create_docker_image () {
    tag="$1"
    echo 'building docker image'
    docker build -t cpuminer:"$tag" "$DIR"
}

# receive tag as argument
push_image () {
    echo 'Pushing image to repository'
    tag="$1"
    docker tag cpuminer:"$tag" 769498303037.dkr.ecr.us-east-1.amazonaws.com/cpuminer:"$tag"
    docker push 769498303037.dkr.ecr.us-east-1.amazonaws.com/cpuminer:"$tag"
}

# Initialize all the option variables.
# This ensures we are not contaminated by variables from the environment.
tag='latest'
push=false

while :; do
    case $1 in
        -h|-\?|--help)
            # display use help
            printf '%s [-t tag_name, --tag=tag_name] [-p, --push]\n' "$0"
            exit
            ;;
        -t|--tag)       # Takes an option argument; ensure it has been specified.
            if [ "$2" ]; then
                tag=$2
                shift
            else
                printf 'ERROR: "--tag" requires a non-empty option argument.\n'
                exit 1
            fi
            ;;
        --tag=?*)
            tag=${1#*=} # Delete everything up to "=" and assign the remainder.
            ;;
        --tag=)         # Handle the case of an empty --tag=
            printf 'ERROR: "--tag" requires a non-empty option argument.\n'
            exit 1
            ;;
        -p|--push)
            push=true
            ;;
        -?*)
            printf 'ERROR: Unknown option: %s\n' "$1" >&2
            exit 1
            ;;
        *)               # Default case: No more options, so break out of the loop.
            break
    esac

    shift
done

create_docker_image "$tag"

if [ "$push" = true ] ; then
    push_image "$tag"
else
    echo 'Image has not been pushed to the repository. If you would like to do so, run with --push'
fi

echo 'Done!'
